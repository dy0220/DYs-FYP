In AWS S3 bucket settings, add bucket policy as below

>{
>  "Version": "2012-10-17",
>  "Statement": [
>    {
>      "Sid": "AllowPublicRead",
>      "Effect": "Allow",
>      "Principal": "*",
>      "Action": "s3:GetObject",
>      "Resource": "arn:aws:s3:::example-storage-name/example-storage-folder/*"
>    }
>  ]
>}
