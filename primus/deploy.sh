#!/bin/bash
echo "🛡️ PRIMUS Deployment Script"
echo "============================"

# Install dependencies
pip install -r requirements.txt

# Run the service
python primus_api.py &
echo "✅ PRIMUS started on http://localhost:8000"

# Open dashboard
sleep 2
start http://localhost:8000/dashboard