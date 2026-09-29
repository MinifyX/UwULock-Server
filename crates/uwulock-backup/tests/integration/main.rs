//! The off-site backups against their three kinds of target: a folder, a small S3 of our own and
//! a small SFTP server of our own, both running inside the test.

mod folder;
mod s3;
mod sftp;
mod support;
