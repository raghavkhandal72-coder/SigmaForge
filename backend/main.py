from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import random

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/rules")
def get_rules():
    return [
        {
            "id": "SIG-001",
            "name": "Suspicious PowerShell Download Cradle",
            "mitre": "T1059.001",
            "status": "Production",
            "precision": 94,
            "recall": 88,
            "fp_rate": 3,
            "last_updated": "2024-08-10"
        },
        {
            "id": "SIG-002",
            "name": "LSASS Memory Dumping",
            "mitre": "T1003.001",
            "status": "Production",
            "precision": 99,
            "recall": 95,
            "fp_rate": 1,
            "last_updated": "2024-08-12"
        },
        {
            "id": "SIG-003",
            "name": "RDP Session Hijacking via tscon",
            "mitre": "T1563.002",
            "status": "Tuning",
            "precision": 72,
            "recall": 91,
            "fp_rate": 14,
            "last_updated": "2024-08-11"
        },
        {
            "id": "SIG-004",
            "name": "Suspicious Child Process of Word",
            "mitre": "T1204.002",
            "status": "Testing",
            "precision": 81,
            "recall": 76,
            "fp_rate": 19,
            "last_updated": "2024-08-12"
        },
        {
            "id": "SIG-005",
            "name": "Clearing Windows Event Logs",
            "mitre": "T1070.001",
            "status": "Production",
            "precision": 97,
            "recall": 92,
            "fp_rate": 2,
            "last_updated": "2024-08-05"
        }
    ]

@app.get("/api/coverage")
def get_coverage():
    return {
        "overall": 78,
        "tactics": [
            {"name": "Initial Access", "score": 82, "rules": 14},
            {"name": "Execution", "score": 91, "rules": 32},
            {"name": "Persistence", "score": 64, "rules": 18},
            {"name": "Privilege Escalation", "score": 71, "rules": 21},
            {"name": "Defense Evasion", "score": 80, "rules": 26},
            {"name": "Credential Access", "score": 76, "rules": 19},
            {"name": "Discovery", "score": 52, "rules": 12},
            {"name": "Lateral Movement", "score": 68, "rules": 15},
            {"name": "Collection", "score": 45, "rules": 8},
            {"name": "Command and Control", "score": 85, "rules": 24},
            {"name": "Exfiltration", "score": 58, "rules": 10},
            {"name": "Impact", "score": 62, "rules": 11}
        ]
    }

@app.get("/api/tests/recent")
def get_recent_tests():
    return [
        {
            "test_id": "TEST-4492",
            "rule": "Suspicious PowerShell Download Cradle",
            "dataset_size": 250000,
            "true_positives": 412,
            "false_positives": 14,
            "false_negatives": 56,
            "status": "Passed"
        },
        {
            "test_id": "TEST-4491",
            "rule": "RDP Session Hijacking via tscon",
            "dataset_size": 180000,
            "true_positives": 89,
            "false_positives": 421,
            "false_negatives": 8,
            "status": "Failed - High Noise"
        }
    ]

@app.get("/api/signal_analysis")
def get_signal_analysis():
    return {
        "trend_data": {
            "labels": ["Sep 08", "Sep 09", "Sep 10", "Sep 11", "Sep 12", "Sep 13", "Sep 14", "Sep 15", "Sep 16", "Sep 17", "Sep 18", "Sep 19", "Sep 20", "Sep 21", "Sep 22"],
            "datasets": [
                {
                    "label": "CrowdStrike Threat Detection Alert (Modified)",
                    "data": [0.1, 0.2, 0.4, 0.7, 0.9, 1.2, 1.4, 1.8, 2.2, 3.1, 2.8, 2.4, 2.1, 1.5, 0.5],
                    "borderColor": "#3b82f6",
                    "backgroundColor": "rgba(59, 130, 246, 0.1)",
                    "fill": True,
                    "tension": 0.4
                }
            ]
        },
        "top_rules": [
            {"name": "CrowdStrike Threat Detection Alert (Modified)", "count": "1,559,233"},
            {"name": "CrowdStrike Threat Detection Alert (Modified)", "count": "1,555,189"},
            {"name": "Threat Intel - Device IP Matched Threat Intel File Hash", "count": "24,144"},
            {"name": "Threat Intel - Device IP Matched Threat Intel File Hash (Modified)", "count": "8,042"},
            {"name": "Failed Authentication Rule", "count": "3,974"},
            {"name": "AWS CloudTrail - Public S3 Bucket Exposed", "count": "777"},
            {"name": "AWS CloudTrail Network Access Control List Deleted", "count": "565"},
            {"name": "Windows Connhost Started Forcefully", "count": "246"},
            {"name": "AWS CloudTrail - Root Console Successful Login Observed", "count": "169"},
            {"name": "PowerShell Encoded Command (Modified)", "count": "114"}
        ],
        "top_expressions": [
            {
                "expression": "metadata_vendor = 'CrowdStrike'\nAND metadata_product = 'Falcon'\nAND metadata_deviceEventId = 'DetectionSummaryEvent'\nAND user_username not like '$'\nAND user_username != ''",
                "count": "3,114,422"
            },
            {
                "expression": "array_contains(listMatches, 'threat') AND array_contains(listMatches, 'column:FileHash')",
                "count": "32,186"
            },
            {
                "expression": "metadata_deviceEventId='Security-4625'",
                "count": "3,974"
            },
            {
                "expression": "metadata_vendor = 'Amazon AWS'\nAND metadata_product = 'CloudTrail'\nAND application = 's3.amazonaws.com'\nAND action in ('CreateBucket', 'PutBucketAcl')\nAND (\nlower(fields['requestParameters.x-amz-acl']) like '%public%'\nor fields['requestParameters.x-amz-grant-read'] like '%AllUsers%'\n)",
                "count": "777"
            }
        ]
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8004, reload=True)
