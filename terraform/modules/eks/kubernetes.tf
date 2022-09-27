provider "kubernetes" {
  host                   = aws_eks_cluster.aptos.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.aptos.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.aptos.token
}

resource "kubernetes_storage_class" "io1" {
  metadata {
    name = "io1"
  }
  storage_provisioner = "kubernetes.io/aws-ebs"
  volume_binding_mode = "WaitForFirstConsumer"
  parameters = {
    type      = "io1"
    iopsPerGB = "50"
  }
}

resource "null_resource" "delete-gp2" {
  provisioner "local-exec" {
    command = <<-EOT
      aws --region ${var.region} eks update-kubeconfig --name ${aws_eks_cluster.aptos.name} --kubeconfig ${local.kubeconfig} &&
      kubectl --kubeconfig ${local.kubeconfig} delete --ignore-not-found storageclass gp2
    EOT
  }

  depends_on = [kubernetes_storage_class.io1]
}


resource "kubernetes_storage_class" "gp2" {
  metadata {
    name = "gp2"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = true
    }
  }
  storage_provisioner = "kubernetes.io/aws-ebs"
  volume_binding_mode = "WaitForFirstConsumer"
  parameters = {
    type = "gp2"
  }

  depends_on = [null_resource.delete-gp2]
}

resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"] # Thumbprint of Root CA for EKS OIDC, Valid until 2037
  url             = aws_eks_cluster.aptos.identity[0].oidc[0].issuer
}

locals {
  oidc_provider = replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")
}

# EBS CSI ADDON

data "aws_iam_policy_document" "aws-ebs-csi-driver-trust-policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.oidc_provider}"
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider}:sub"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "aws-ebs-csi-driver" {
  name                 = "aptos-${local.workspace_name}-ebs-csi-controller"
  path                 = var.iam_path
  permissions_boundary = var.permissions_boundary_policy
  assume_role_policy   = data.aws_iam_policy_document.aws-ebs-csi-driver-trust-policy.json
}

resource "aws_iam_role_policy_attachment" "caws-ebs-csi-driver" {
  role = aws_iam_role.aws-ebs-csi-driver.name
  # From this reference: https://docs.aws.amazon.com/eks/latest/userguide/csi-iam-role.html
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_eks_addon" "aws-ebs-csi-driver" {
  cluster_name             = aws_eks_cluster.aptos.name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = aws_iam_role.aws-ebs-csi-driver.arn
}


resource "kubernetes_storage_class" "gp3" {
  metadata {
    name = "gp3"
  }
  storage_provisioner = "ebs.csi.aws.com"
  volume_binding_mode = "WaitForFirstConsumer"
  parameters = {
    type = "gp3"
  }

  depends_on = [null_resource.delete-gp2, aws_eks_addon.aws-ebs-csi-driver]
}


resource "kubernetes_role_binding" "psp-kube-system" {
  metadata {
    name      = "eks:podsecuritypolicy:privileged"
    namespace = "kube-system"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "eks:podsecuritypolicy:privileged"
  }

  subject {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Group"
    name      = "system:serviceaccounts:kube-system"
  }
}

locals {
  kubeconfig = "/tmp/kube.config.${md5(timestamp())}"
}

resource "null_resource" "delete-psp-authenticated" {
  provisioner "local-exec" {
    command = <<-EOT
      aws --region ${var.region} eks update-kubeconfig --name ${aws_eks_cluster.aptos.name} --kubeconfig ${local.kubeconfig} &&
      kubectl --kubeconfig ${local.kubeconfig} delete --ignore-not-found clusterrolebinding eks:podsecuritypolicy:authenticated
    EOT
  }

  depends_on = [kubernetes_role_binding.psp-kube-system]
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.aptos.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.aptos.certificate_authority.0.data)
    token                  = data.aws_eks_cluster_auth.aptos.token
  }
}

resource "kubernetes_namespace" "tigera-operator" {
  metadata {
    annotations = {
      name = "tigera-operator"
    }

    name = "tigera-operator"
  }
}

resource "helm_release" "calico" {
  name       = "calico"
  repository = "https://docs.projectcalico.org/charts"
  chart      = "tigera-operator"
  version    = "3.23.3"
  namespace  = "tigera-operator"
  depends_on = [
    kubernetes_namespace.tigera-operator
  ]
}

resource "kubernetes_cluster_role" "debug" {
  metadata {
    name = "debug"
  }

  rule {
    api_groups = [""]
    resources  = ["pods/portforward", "pods/exec"]
    verbs      = ["create"]
  }
}

resource "kubernetes_role_binding" "debuggers" {
  metadata {
    name = "debuggers"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.debug.metadata[0].name
  }

  subject {
    kind = "Group"
    name = "debuggers"
  }
}

resource "kubernetes_role_binding" "viewers" {
  metadata {
    name = "viewers"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }

  subject {
    kind = "Group"
    name = "viewers"
  }
  subject {
    kind = "Group"
    name = "debuggers"
  }
}

resource "kubernetes_config_map" "aws-auth" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapRoles = yamlencode(concat(
      [{
        rolearn  = aws_iam_role.nodes.arn
        username = "system:node:{{EC2PrivateDNSName}}"
        groups   = ["system:bootstrappers", "system:nodes"]
      }],
      var.iam_path == "/" ? [] : [{
        # Workaround for https://github.com/kubernetes-sigs/aws-iam-authenticator/issues/268
        # The entry above is still needed otherwise EKS marks the node group as unhealthy
        rolearn  = replace(aws_iam_role.nodes.arn, "role${var.iam_path}", "role/")
        username = "system:node:{{EC2PrivateDNSName}}"
        groups   = ["system:bootstrappers", "system:nodes"]
      }],
      [for role in var.k8s_admin_roles : {
        rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${role}"
        username = "${role}:{{SessionName}}"
        groups   = ["system:masters"]
      }],
      [for role in var.k8s_viewer_roles : {
        rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${role}"
        username = "${role}:{{SessionName}}"
        groups   = ["viewers"]
      }],
      [for role in var.k8s_debugger_roles : {
        rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${role}"
        username = "${role}:{{SessionName}}"
        groups   = ["debuggers"]
      }],
    ))
    mapUsers = yamlencode(concat(
      [for user in var.k8s_admins : {
        userarn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${user}"
        username = user
        groups   = ["system:masters"]
      }],
      [for user in var.k8s_viewers : {
        userarn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${user}"
        username = user
        groups   = ["viewers"]
      }],
      [for user in var.k8s_debuggers : {
        userarn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${user}"
        username = user
        groups   = ["debuggers"]
      }],
    ))
  }
}

resource "local_file" "kubernetes" {
  filename = "${local.workspace_name}-kubernetes.json"
  content = jsonencode({
    kubernetes_host        = aws_eks_cluster.aptos.endpoint
    kubernetes_ca_cert     = base64decode(aws_eks_cluster.aptos.certificate_authority.0.data)
    issuer                 = aws_eks_cluster.aptos.identity[0].oidc[0].issuer
    service_account_prefix = "aptos-pfn"
    pod_cidrs              = aws_subnet.private[*].cidr_block
  })
  file_permission = "0644"
}

output "kubernetes" {
  value     = jsondecode(local_file.kubernetes.content)
  sensitive = true
}
