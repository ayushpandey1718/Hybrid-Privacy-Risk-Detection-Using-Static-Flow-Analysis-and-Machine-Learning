import gzip
import pickle
import os
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier

# Dummy dataset for training
# Features: [entropy, file_size]
X = np.array([
    [7.5, 50000],  # high entropy, suspect malicious
    [7.8, 120000], # high entropy, suspect malicious
    [2.1, 50000],  # low entropy, benign
    [4.5, 30000],  # medium entropy, benign
    [7.2, 1000],   # high entropy, small file, malicious
    [3.1, 1000000] # low entropy, large file, benign
])
y = np.array([1, 1, 0, 0, 1, 0])

clf = ExtraTreesClassifier(n_estimators=100, random_state=42)
clf.fit(X, y)

model_dir = "vs/models"
if not os.path.exists(model_dir):
    os.makedirs(model_dir)

model_path = os.path.join(model_dir, "classifier-model-new.pkl.gz")
with gzip.open(model_path, 'wb') as f:
    pickle.dump(clf, f)

print(f"Model saved to {model_path}")
