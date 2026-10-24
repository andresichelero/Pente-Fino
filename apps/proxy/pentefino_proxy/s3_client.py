from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Union

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    Config = None  # type: ignore
    ClientError = Exception  # type: ignore

logger = logging.getLogger("pentefino.proxy.s3_client")


class InMemoryS3Store:
    """In-memory S3 storage mock for offline test suites."""

    def __init__(self):
        self._buckets: Dict[str, Dict[str, bytes]] = {"evidence": {}}

    def ensure_bucket(self, bucket_name: str) -> bool:
        if bucket_name not in self._buckets:
            self._buckets[bucket_name] = {}
        return True

    def put_object(self, bucket_name: str, key: str, data: bytes) -> str:
        self.ensure_bucket(bucket_name)
        self._buckets[bucket_name][key] = data
        return key

    def get_object(self, bucket_name: str, key: str) -> bytes:
        if bucket_name not in self._buckets or key not in self._buckets[bucket_name]:
            raise KeyError(f"Key {key} not found in bucket {bucket_name}")
        return self._buckets[bucket_name][key]

    def has_object(self, bucket_name: str, key: str) -> bool:
        return bucket_name in self._buckets and key in self._buckets[bucket_name]


class S3EvidenceClient:
    """
    S3 Client for uploading forensic interaction artifacts to SeaweedFS S3.
    Default endpoint: http://127.0.0.1:8333, bucket: 'evidence'.
    """

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        default_bucket: str = "evidence",
        use_mock: bool = False,
    ):
        self.endpoint_url = (
            endpoint_url
            or os.environ.get("SEAWEEDFS_S3_ENDPOINT")
            or "http://127.0.0.1:8333"
        )
        self.access_key = (
            access_key
            or os.environ.get("SEAWEEDFS_ACCESS_KEY")
            or "pentefino_s3_admin"
        )
        self.secret_key = (
            secret_key
            or os.environ.get("SEAWEEDFS_SECRET_KEY")
            or "pentefino_s3_secret"
        )
        self.default_bucket = default_bucket
        self.use_mock = use_mock

        self._mock_store = InMemoryS3Store()
        self._client = None

        if not self.use_mock and boto3 is not None:
            try:
                cfg = Config(
                    s3={"addressing_style": "path"},
                    signature_version="s3v4",
                    connect_timeout=2,
                    read_timeout=5,
                    retries={"max_attempts": 2},
                )
                self._client = boto3.client(
                    "s3",
                    endpoint_url=self.endpoint_url,
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    config=cfg,
                    region_name="us-east-1",
                )
            except Exception as e:
                logger.warning("Failed to initialize boto3 S3 client (%s); using in-memory mock", e)
                self.use_mock = True

    def ensure_bucket(self, bucket_name: Optional[str] = None) -> bool:
        """Ensures the specified bucket exists, creating it if necessary."""
        bucket = bucket_name or self.default_bucket
        if self.use_mock or self._client is None:
            return self._mock_store.ensure_bucket(bucket)

        try:
            self._client.head_bucket(Bucket=bucket)
            return True
        except ClientError as e:
            error_code = str(e.response.get("Error", {}).get("Code", ""))
            if error_code in ("404", "NoSuchBucket"):
                try:
                    self._client.create_bucket(Bucket=bucket)
                    return True
                except Exception as ce:
                    logger.warning("Could not create bucket %s: %s", bucket, ce)
            return False
        except Exception as ex:
            logger.warning("Error checking bucket %s: %s; falling back to mock", bucket, ex)
            return self._mock_store.ensure_bucket(bucket)

    def upload_evidence(
        self,
        artifact_data: Union[bytes, str],
        object_key: str,
        bucket_name: Optional[str] = None,
        content_type: str = "application/json",
        content_encoding: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Uploads sanitized evidence bytes to SeaweedFS S3 bucket.
        Returns the object key.
        """
        bucket = bucket_name or self.default_bucket
        data_bytes = (
            artifact_data.encode("utf-8")
            if isinstance(artifact_data, str)
            else artifact_data
        )

        if self.use_mock or self._client is None:
            self._mock_store.put_object(bucket, object_key, data_bytes)
            return object_key

        try:
            self.ensure_bucket(bucket)
            extra_args: Dict[str, Any] = {"ContentType": content_type}
            if content_encoding:
                extra_args["ContentEncoding"] = content_encoding
            if metadata:
                extra_args["Metadata"] = metadata

            self._client.put_object(
                Bucket=bucket,
                Key=object_key,
                Body=data_bytes,
                **extra_args,
            )
            return object_key
        except Exception as e:
            logger.warning("Failed to upload to real S3 (%s); saving to mock store", e)
            self._mock_store.put_object(bucket, object_key, data_bytes)
            return object_key

    def get_evidence(self, object_key: str, bucket_name: Optional[str] = None) -> bytes:
        """Retrieves evidence object from S3."""
        bucket = bucket_name or self.default_bucket
        if self.use_mock or self._client is None:
            return self._mock_store.get_object(bucket, object_key)

        try:
            resp = self._client.get_object(Bucket=bucket, Key=object_key)
            return resp["Body"].read()
        except Exception as e:
            if self._mock_store.has_object(bucket, object_key):
                return self._mock_store.get_object(bucket, object_key)
            raise e

    def exists(self, object_key: str, bucket_name: Optional[str] = None) -> bool:
        """Checks if an evidence object exists in the S3 bucket."""
        bucket = bucket_name or self.default_bucket
        if self._mock_store.has_object(bucket, object_key):
            return True
        if self.use_mock or self._client is None:
            return False
        try:
            self._client.head_object(Bucket=bucket, Key=object_key)
            return True
        except Exception:
            return False
