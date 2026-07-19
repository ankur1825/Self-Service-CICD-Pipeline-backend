# AWS nonproduction real-execution gate evidence

Date: 2026-07-18 (America/New_York)

## Scope

This evidence covers the read-only real-AWS gate for the client-hosted Cloud
Migration Factory. It does not authorize or claim source registration,
replication, test launch, cutover, rollback, or finalization.

| Item | Validated value |
| --- | --- |
| AWS account | `426946630837` |
| Region | `us-east-1` |
| EKS cluster | `horizon-eks-dev` |
| VPC | `vpc-0302403e56e376e70` (`10.20.0.0/16`) |
| MGN staging subnet | `subnet-0d1d4e1eaef722020` (`us-east-1a`) |
| Test-launch subnet | `subnet-0846218a2cda316cc` (`us-east-1b`) |
| Real-worker namespace | `horizon-cloud-migration-aws-sandbox` |
| Immutable backend image | `sha256:debd0154be9d13bbfe1482567b3770c739be8a28fadf6fce8a0d4ebb73f45efd` |

Both subnets belong to the EKS VPC, are available `/24` public subnets, and use
an active `0.0.0.0/0` route to Internet Gateway `igw-0a2b726d332f45118`.

## AWS changes made

- Created and policy-attached the AWS-documented MGN prerequisite roles.
- Initialized MGN in `us-east-1`.
- Enabled EBS encryption by default in `us-east-1`. Existing EBS resources were
  not changed; new regional EBS volumes and snapshots use `alias/aws/ebs`.
- Created MGN replication template `rct-78da6e92f55659c02`:
  - staging subnet `subnet-0d1d4e1eaef722020`
  - `PUBLIC_IP` data-plane routing and public replication-server IPs
  - `t3.small` replication server and GP3 large staging disks
  - default EBS encryption
- Created MGN launch template `lct-d9bae65804984c2d6`:
  - launch disposition `STOPPED`
  - no private-IP copy
  - public IP association enabled for this public-subnet sandbox
  - source boot mode retained
- Created IRSA role `horizon-cloud-migration-aws-sandbox-worker`.
- Created target role `HorizonCloudMigrationSandboxExecutionRole` with only
  `mgn:DescribeJobs` and `mgn:DescribeSourceServers`.
- Stored the STS external ID only in Kubernetes Secret
  `cloud-migration-aws-external-id`; its value is not in Git or this evidence.

## Preflight result

Job `horizon-cloud-migration-aws-preflight` completed successfully in eight
seconds with zero restarts. Sanitized result:

```json
{
  "region": "us-east-1",
  "checks": [
    {"name": "tls:sts.us-east-1.amazonaws.com", "status": "PASS"},
    {"name": "tls:mgn.us-east-1.amazonaws.com", "status": "PASS"},
    {"name": "irsa_identity", "status": "PASS", "account": "426946630837"},
    {"name": "target_role_identity", "status": "PASS", "account": "426946630837"},
    {"name": "mgn_read", "status": "PASS", "source_server_count": 0}
  ]
}
```

The existing mock/UAT deployments in `horizon-cloud-migration-dev` remained at
one ready replica each and retained their immutable main-merge image tags.

## Open gates

1. Identify one disposable, non-sensitive source server and record hostname,
   IP, operating system, source type, and owner approval.
2. From the actual source network, validate TCP/443 to MGN APIs and TCP/1500 to
   the MGN replication servers. The EKS worker cannot prove this path.
3. Install the AWS Replication Agent and wait for initial sync; record its MGN
   `s-...` source-server ID.
4. Configure that source server's EC2 launch template to use test subnet
   `subnet-0846218a2cda316cc`, an approved security group, a right-sized instance
   type, and required tags.
5. Expand the target role only to `mgn:StartTest` for the approved source and
   run the test-launch/rollback gate. Keep cutover and finalization disabled.

AWS references:

- https://docs.aws.amazon.com/mgn/latest/ug/mgn-initialize-api.html
- https://docs.aws.amazon.com/mgn/latest/ug/ebs-storage.html
- https://docs.aws.amazon.com/mgn/latest/ug/preparing-environments.html
- https://docs.aws.amazon.com/mgn/latest/ug/launching-test-gs.html
