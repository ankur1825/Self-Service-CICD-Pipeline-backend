# AWS client-hosted execution worker IAM

This directory separates the worker identity from the target-account execution identity:

1. Apply `worker-irsa` in the AWS account that hosts the client's Horizon EKS installation.
2. Apply `target-role` in the migration target account with `execution_enabled = false`.
3. Configure the Environment Catalog `target_aws_role_arn` with the target-role output.
4. Annotate the worker Kubernetes service account with the worker-role output.
5. Store the optional STS external ID in a Kubernetes Secret and reference it with
   `cloudMigration.worker.awsExternalIdSecret`; do not put it in Git or values files.
6. Run PRELIGHT and RECONCILE jobs. Only after client approval, change
   `execution_enabled = true` and enable the product execution lock.

The worker uses 15-minute STS sessions and supplies an action-specific session policy.
The effective permissions are the intersection of that session policy and the target
role policy. Temporary credentials are held in memory and are never stored in the
Horizon database or evidence artifacts.

AWS references:

- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- https://docs.aws.amazon.com/mgn/latest/APIReference/API_Operations.html
- https://docs.aws.amazon.com/mgn/latest/ug/preparing-environments.html
