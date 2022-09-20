mod error;

use aptos_executor_types::ExecutedChunk;
use aptos_types::{contract_event::ContractEvent, transaction::Transaction as AptosTx};
pub use error::*;
use fastcrypto::encoding::{Encoding, Hex};
use mamoru_aptos_types::{
    Block, BlockBatch, CallTrace, CallTraceArg, CallTraceArgBatch, CallTraceBatch,
    CallTraceTypeArg, CallTraceTypeArgBatch, Event, EventBatch, Transaction, TransactionBatch,
};
use mamoru_sniffer::{
    core::{BlockchainDataCtxBuilder, StructValue, Value, ValueData},
    *,
};
use move_core_types::{
    trace::{CallTrace as MoveCallTrace, CallType as MoveCallType},
    value::{MoveStruct, MoveValue},
};
use rayon::prelude::*;
use std::collections::HashMap;
use tracing::{error, span, Level};

pub struct AptosSniffer {
    inner: Sniffer,
}

impl AptosSniffer {
    pub async fn new() -> Result<Self, AptosSnifferError> {
        let inner =
            Sniffer::new(SnifferConfig::from_env().expect("Missing environment variables")).await?;

        Ok(Self { inner })
    }

    pub async fn observe_block(&self, chunk: ExecutedChunk) -> Result<(), AptosSnifferError> {
        let block_info = if let Some(block_info) = &chunk.ledger_info {
            block_info.commit_info()
        } else {
            error!(
                "Missing ledger info! The node is either bootstrapping or it's epoch end chunk."
            );

            return Ok(());
        };

        let block_hash = block_info.id().to_hex_literal();

        let span = span!(Level::DEBUG, "ctx_builder", %block_hash);
        let _guard = span.enter();

        let ctx_builder = BlockchainDataCtxBuilder::new();

        ctx_builder.add_data(
            BlockBatch::new(vec![Block {
                hash: block_hash.clone(),
                epoch: block_info.epoch(),
                timestamp_usecs: block_info.timestamp_usecs(),
            }])
            .boxed(),
        )?;

        let mut call_traces = vec![];
        let mut call_trace_args = vec![];
        let mut call_trace_type_args = vec![];
        let mut events = vec![];

        let transactions: Vec<_> = chunk
            .to_commit
            .into_iter()
            .zip(0u64..)
            .filter_map(|((tx, mut tx_data), seq)| {
                let move_call_traces = std::mem::take(&mut tx_data.call_traces);

                let status = match tx_data.status().status() {
                    Ok(_) => 0,
                    Err(code) => code as u64,
                };

                if let AptosTx::UserTransaction(tx) = tx {
                    register_events(&mut events, seq, tx_data.events());
                    register_call_traces(
                        &mut call_traces,
                        &mut call_trace_type_args,
                        &mut call_trace_args,
                        seq,
                        move_call_traces.to_vec(),
                    );

                    Some(Transaction {
                        seq,
                        block_hash: block_hash.clone(),
                        hash: tx_data.txn_info_hash().to_hex_literal(),
                        event_root_hash: tx_data.event_root_hash().to_hex_literal(),
                        state_change_hash: tx_data.state_change_hash().to_hex_literal(),
                        gas_used: tx_data.gas_used(),
                        max_gas_amount: tx.max_gas_amount(),
                        gas_unit_price: tx.gas_unit_price(),
                        expiration_timestamp_secs: tx.expiration_timestamp_secs(),
                        status,
                        sender: tx.sender().to_hex_literal(),
                        sequence_number: tx.sequence_number(),
                    })
                } else {
                    // skipping service transactions like block metadata
                    None
                }
            })
            .collect();

        ctx_builder.add_data(CallTraceBatch::new(call_traces).boxed())?;
        ctx_builder.add_data(CallTraceTypeArgBatch::new(call_trace_type_args).boxed())?;
        ctx_builder.add_data(CallTraceArgBatch::new(call_trace_args).boxed())?;
        ctx_builder.add_data(EventBatch::new(events).boxed())?;

        ctx_builder.add_data(TransactionBatch::new(transactions).boxed())?;

        let ctx = ctx_builder.finish(block_hash.clone(), block_hash);

        self.inner.observe_data(ctx).await;

        Ok(())
    }
}

fn register_call_traces(
    mamoru_call_traces: &mut Vec<CallTrace>,
    mamoru_call_trace_type_args: &mut Vec<CallTraceTypeArg>,
    mamoru_call_trace_args: &mut Vec<CallTraceArg>,
    tx_seq: u64,
    move_call_traces: Vec<MoveCallTrace>,
) {
    let call_traces_len = move_call_traces.len();

    let (call_traces, (args, type_args)): (Vec<_>, (Vec<_>, Vec<_>)) = move_call_traces
        .into_par_iter()
        .zip(0..call_traces_len)
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

            for (arg, seq) in trace.ty_args.into_iter().zip(0u64..) {
                cta.push(CallTraceTypeArg {
                    seq,
                    call_trace_seq: trace_seq,
                    arg: arg.to_canonical_string(),
                });
            }

            for (arg, seq) in trace.args.into_iter().zip(0u64..) {
                match ValueData::new(to_value(&arg)) {
                    Some(arg) => {
                        ca.push(CallTraceArg {
                            seq,
                            call_trace_seq: trace_seq,
                            arg,
                        });
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
        mamoru_events.push(Event {
            tx_seq,
            key: format!("{:#x}", event.key()),
            sequence_number: event.sequence_number(),
            typ: event.type_tag().to_canonical_string(),
            data: event.event_data().to_vec(),
        })
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
