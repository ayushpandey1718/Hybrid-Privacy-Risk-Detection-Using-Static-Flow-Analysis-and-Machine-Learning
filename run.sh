#!/bin/bash
# Wrapper to setup and run the malware detection scanners
set -e

echo "=== Setup Virtual Environment and Dependencies ==="
# Setup virtualenv and install requirements if not already present
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install numpy scikit-learn xgboost matplotlib
else
    source venv/bin/activate
fi

# Ensure a compatible ML model is present
if [ ! -f "vs/models/classifier-model-new.pkl.gz" ]; then
    echo "=== Training compatibility ML model ==="
    python train_dummy_model.py
fi

echo ""
echo "=== Running Simple Scanner on README.md ==="
python scanner.py README.md --model vs/models/classifier-model-new.pkl.gz

echo ""
echo "=== Running Entropy Visualizer on README.md ==="
python visualize_entropy.py README.md -o output_entropy_plot.png

echo ""
echo "=== Running Threat Analysis on README.md ==="
python threat_analysis.py README.md --verbose

echo ""
echo "=== Launching Threat Intelligence Dashboard ==="
echo "Opening http://localhost:8080/threat_dashboard.html in your browser..."
python -m http.server 8080 &
SERVER_PID=$!
sleep 1
open "http://localhost:8080/threat_dashboard.html" 2>/dev/null || xdg-open "http://localhost:8080/threat_dashboard.html" 2>/dev/null || echo "Open http://localhost:8080/threat_dashboard.html in your browser"

echo ""
echo "All done! Dashboard running at http://localhost:8080/threat_dashboard.html"
echo "Entropy plot saved to 'output_entropy_plot.png'"
echo "Press Ctrl+C to stop the dashboard server."
wait $SERVER_PID
