use aptos_crypto::hash::CryptoHash;
use aptos_types::{
    block_info::BlockInfo,
    contract_event::ContractEvent,
    transaction::{ExecutionStatus, Transaction as AptosTx, TransactionToCommit},
};
pub use error::*;
use fastcrypto::encoding::{Encoding, Hex};
use itertools::Itertools;
use mamoru_aptos_types::{
    AptosCtx, Block, CallTrace, CallTraceArg, CallTraceTypeArg, Event, Transaction,
};
use mamoru_sniffer::{
    core::{BlockchainDataBuilder, StructValue, Value, ValueData},
    *,
};
use move_core_types::{
    trace::{CallTrace as MoveCallTrace, CallType as MoveCallType},
    value::{MoveStruct, MoveValue},
    vm_status::StatusCode,
};
use std::{collections::HashMap, mem::size_of_val, sync::Arc};
use tracing::{error, info};

mod error;

pub struct AptosSniffer {
    inner: Sniffer,
}

impl AptosSniffer {
    pub async fn new() -> Result<Self, AptosSnifferError> {
        let inner =
            Sniffer::new(SnifferConfig::from_env().expect("Missing environment variables")).await?;

        Ok(Self { inner })
    }

    #[tracing::instrument(
        skip_all,
        fields(
            block_hash = block_info.id().to_hex_literal(),
            level = "debug",
        ),
    )]
    pub async fn observe_block(
        &self,
        block_info: BlockInfo,
        to_commit: Vec<TransactionToCommit>,
        emit_debug_info: bool,
    ) -> Result<(), AptosSnifferError> {
        if emit_debug_info {
            emit_debug_stats(&to_commit);
        }

        let block_hash = block_info.id().to_hex_literal();
        let block_id = format!("{}", block_info.version());
        let mut builder = BlockchainDataBuilder::<AptosCtx>::new();

        builder.set_block_data(block_id, block_hash.clone());

        builder.data_mut().set_block(Block {
            hash: block_hash.clone(),
            epoch: block_info.epoch(),
            timestamp_usecs: block_info.timestamp_usecs(),
        });

        let mut call_traces = vec![];
        let mut call_trace_args = vec![];
        let mut call_trace_type_args = vec![];
        let mut events = vec![];

        let transactions: Vec<_> = to_commit
            .into_iter()
            .filter_map(|to_commit| {
                let tx_hash = to_commit.transaction.hash().to_hex_literal();

                if let AptosTx::UserTransaction(user_tx) = &to_commit.transaction {
                    // skipping service transactions like block metadata
                    Some((tx_hash, user_tx.clone(), to_commit))
                } else {
                    None
                }
            })
            .zip(0u64..)
            .map(|((tx_hash, user_tx, mut tx_to_commit), seq)| {
                let status = match tx_to_commit.status() {
                    ExecutionStatus::Success => 0,
                    ExecutionStatus::OutOfGas => 1,
                    ExecutionStatus::MoveAbort {
                        location: _,
                        code,
                        info: _,
                    } => *code,
                    ExecutionStatus::ExecutionFailure { .. } => {
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR as u64
                    },
                    ExecutionStatus::MiscellaneousError(err) => match err {
                        None => StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR as u64,
                        Some(code) => (*code).into(),
                    },
                };

                register_events(&mut events, seq, tx_to_commit.events());
                register_call_traces(
                    &mut call_traces,
                    &mut call_trace_type_args,
                    &mut call_trace_args,
                    seq,
                    std::mem::take(&mut tx_to_commit.call_traces),
                );

                Transaction {
                    seq,
                    block_hash: block_hash.clone(),
                    hash: tx_hash,
                    event_root_hash: tx_to_commit
                        .transaction_info
                        .event_root_hash()
                        .to_hex_literal(),
                    state_change_hash: tx_to_commit
                        .transaction_info
                        .state_change_hash()
                        .to_hex_literal(),
                    gas_used: tx_to_commit.gas_used(),
                    max_gas_amount: user_tx.max_gas_amount(),
                    gas_unit_price: user_tx.gas_unit_price(),
                    expiration_timestamp_secs: user_tx.expiration_timestamp_secs(),
                    status,
                    sender: user_tx.sender().to_hex_literal(),
                    sequence_number: user_tx.sequence_number(),
                }
            })
            .collect();

        builder.set_statistics(
            1,
            transactions.len() as u64,
            events.len() as u64,
            call_traces.len() as u64,
        );

        builder.data_mut().transactions.extend(transactions);
        builder.data_mut().call_traces.extend(call_traces);
        builder.data_mut().call_trace_args.extend(call_trace_args);
        builder
            .data_mut()
            .call_trace_type_args
            .extend(call_trace_type_args);
        builder.data_mut().events.extend(events);

        let ctx = builder.build()?;

        self.inner.observe_data(ctx).await;

        Ok(())
    }
}

fn emit_debug_stats(to_commit: &[TransactionToCommit]) {
    let cache_hits_count: usize = to_commit
        .iter()
        .flat_map(|to_commit| &to_commit.call_traces)
        .map(|trace| {
            trace
                .args
                .iter()
                // If arc has copies, it's one cache hit.
                .map(|a| if Arc::strong_count(a) > 1 { 1 } else { 0 })
                .sum::<usize>()
        })
        .sum();

    let total_size: usize = to_commit
        .iter()
        .flat_map(|to_commit| &to_commit.call_traces)
        .map(|trace| trace.args.iter().map(|a| move_value_size(a)).sum::<usize>())
        .sum();

    let total_call_traces = to_commit
        .iter()
        .flat_map(|to_commit| &to_commit.call_traces)
        .count();

    let top_sized_traces = to_commit
        .iter()
        .flat_map(|to_commit| &to_commit.call_traces)
        .map(|trace| trace.args.iter().map(|a| move_value_size(a)).sum::<usize>())
        .collect::<Vec<_>>()
        .into_iter()
        .sorted()
        .rev()
        .take(50)
        .map(bytes_to_human_readable)
        .collect::<Vec<_>>();

    let mut function_call_frequency: HashMap<String, usize> = HashMap::new();

    for trace in to_commit
        .iter()
        .flat_map(|to_commit| &to_commit.call_traces)
    {
        let function = trace
            .module_id
            .as_ref()
            .map(|module| format!("{}::{}", module, &trace.function));

        if let Some(function) = function {
            let count = function_call_frequency.entry(function.clone()).or_insert(0);
            *count += 1;
        }
    }

    let mut most_frequent_calls: Vec<(_, _)> = function_call_frequency.into_iter().collect();

    most_frequent_calls.sort_by(|(_, a), (_, b)| b.cmp(a));
    most_frequent_calls.truncate(50);

    let top_heavy_contracts: Vec<_> = to_commit
        .iter()
        .map(|to_commit| &to_commit.call_traces)
        .filter_map(|traces| {
            let Some(first) = traces.first() else {
                return None;
            };

            let Some(module_id) = first.module_id.as_ref() else {
                return None;
            };

            let total_size: usize = traces
                .iter()
                .map(|trace| trace.args.iter().map(|a| move_value_size(a)).sum::<usize>())
                .sum();

            Some((format!("{}::{}", module_id, &first.function), total_size))
        })
        .sorted_by(|(_, a), (_, b)| b.cmp(a))
        .take(50)
        .map(|(name, size)| (name, bytes_to_human_readable(size)))
        .collect();

    info!(
        total_call_traces = total_call_traces,
        cache_hits_count = %cache_hits_count,
        top_sized_traces = ?top_sized_traces,
        most_frequent_calls = ?most_frequent_calls,
        top_heavy_contracts = ?top_heavy_contracts,
        total_size = bytes_to_human_readable(total_size),
        "call traces debug info"
    );
}

fn move_value_size(value: &MoveValue) -> usize {
    let internal_value_size = match value {
        MoveValue::U8(value) => size_of_val(value),
        MoveValue::U64(value) => size_of_val(value),
        MoveValue::U128(value) => size_of_val(value),
        MoveValue::Bool(value) => size_of_val(value),
        MoveValue::Address(value) => size_of_val(value),
        MoveValue::Vector(value) => value.iter().map(move_value_size).sum::<usize>(),
        MoveValue::Struct(value) => match value {
            MoveStruct::Runtime(values) => values.iter().map(move_value_size).sum::<usize>(),
            MoveStruct::WithFields(fields) => fields
                .iter()
                .map(|(a, b)| size_of_val(a) + move_value_size(b))
                .sum::<usize>(),
            MoveStruct::WithTypes { type_, fields } => {
                size_of_val(type_)
                    + fields
                        .iter()
                        .map(|(a, b)| size_of_val(a) + move_value_size(b))
                        .sum::<usize>()
            },
        },
        MoveValue::Signer(value) => size_of_val(value),
        MoveValue::U16(value) => size_of_val(value),
        MoveValue::U32(value) => size_of_val(value),
        MoveValue::U256(value) => size_of_val(value),
    };

    internal_value_size + std::mem::size_of::<MoveValue>()
}

fn bytes_to_human_readable(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;

    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    }
}

fn register_call_traces(
    mamoru_call_traces: &mut Vec<CallTrace>,
    mamoru_call_trace_type_args: &mut Vec<CallTraceTypeArg>,
    mamoru_call_trace_args: &mut Vec<CallTraceArg>,
    tx_seq: u64,
    move_call_traces: Vec<MoveCallTrace>,
) {
    let call_traces_len = mamoru_call_traces.len();
    let mut call_trace_args_len = mamoru_call_trace_args.len();
    let mut call_trace_type_args_len = mamoru_call_trace_type_args.len();

    let (call_traces, (args, type_args)): (Vec<_>, (Vec<_>, Vec<_>)) = move_call_traces
        .into_iter()
        .zip(call_traces_len..)
        .map(|(trace, trace_seq)| {
            let trace_seq = trace_seq as u64;

            let call_trace = CallTrace {
                seq: trace_seq,
                tx_seq,
                depth: trace.depth,
                call_type: match trace.call_type {
                    MoveCallType::Call => 0,
                    MoveCallType::CallGeneric => 1,
                },
                gas_used: trace.gas_used,
                transaction_module: trace.module_id.map(|module| module.short_str_lossless()),
                function: trace.function.to_string(),
            };

            let mut cta = vec![];
            let mut ca = vec![];

            for (arg, seq) in trace
                .ty_args
                .into_iter()
                .zip(call_trace_type_args_len as u64..)
            {
                cta.push(CallTraceTypeArg {
                    seq,
                    call_trace_seq: trace_seq,
                    arg: arg.to_canonical_string(),
                });

                call_trace_type_args_len += 1;
            }

            for (arg, seq) in trace.args.into_iter().zip(call_trace_args_len as u64..) {
                match ValueData::new(to_value(&arg)) {
                    Some(arg) => {
                        ca.push(CallTraceArg {
                            seq,
                            call_trace_seq: trace_seq,
                            arg,
                        });

                        call_trace_args_len += 1;
                    },
                    None => continue,
                }
            }

            (call_trace, (ca, cta))
        })
        .unzip();

    mamoru_call_traces.extend(call_traces);
    mamoru_call_trace_type_args.extend(type_args.into_iter().flatten().collect::<Vec<_>>());
    mamoru_call_trace_args.extend(args.into_iter().flatten().collect::<Vec<_>>());
}

fn register_events(mamoru_events: &mut Vec<Event>, tx_seq: u64, events: &[ContractEvent]) {
    for event in events {
        match event {
            ContractEvent::V1(event) => {
                mamoru_events.push(Event {
                    tx_seq,
                    key: format!("{:#x}", event.key()),
                    sequence_number: event.sequence_number(),
                    typ: event.type_tag().to_canonical_string(),
                    data: event.event_data().to_vec(),
                });
            },
            ContractEvent::V2(event) => {
                mamoru_events.push(Event {
                    tx_seq,
                    key: "".to_string(),
                    sequence_number: 0,
                    typ: event.type_tag().to_canonical_string(),
                    data: event.event_data().to_vec(),
                });
            },
        }
    }
}

fn format_object_id<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", Hex::encode(data))
}

fn to_value(data: &MoveValue) -> Value {
    match data {
        MoveValue::Bool(value) => Value::Bool(*value),
        MoveValue::U8(value) => Value::U64(*value as u64),
        MoveValue::U16(value) => Value::U64(*value as u64),
        MoveValue::U32(value) => Value::U64(*value as u64),
        MoveValue::U64(value) => Value::U64(*value),
        MoveValue::U128(value) => Value::String(format!("{:#x}", value)),
        MoveValue::U256(value) => Value::String(format!("{:#x}", value)),
        MoveValue::Address(addr) | MoveValue::Signer(addr) => Value::String(format_object_id(addr)),
        MoveValue::Vector(value) => Value::List(value.iter().map(to_value).collect()),
        MoveValue::Struct(value) => {
            let struct_value = match value {
                MoveStruct::WithTypes { type_, fields } => StructValue::new(
                    type_.to_canonical_string(),
                    fields
                        .iter()
                        .map(|(field, value)| (field.clone().into_string(), to_value(value)))
                        .collect(),
                ),

                _ => {
                    error!("BUG: received undecorated `MoveStruct`.");

                    StructValue::new("unknown".to_string(), HashMap::new())
                },
            };

            Value::Struct(struct_value)
        },
    }
}
