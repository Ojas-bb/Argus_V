# Argus_V Engineering Journal

## 00. Architectural Critique: "The Cold Start Problem"
**Date:** October 26, 2023
**Focus:** `aegis.model_manager.ModelManager`

### The Status Quo
The current implementation of `Argus_V` relies on a "Fall-Back Model" when no pre-trained model is found locally or in Firebase.
This fallback logic (`_use_fallback_model` in `model_manager.py`) instantiates an `IsolationForest` and fits it on `np.random.randn(200, n_features)`.

### The Problem
This is "Security Theater."
1.  **Randomness is not a Baseline:** Training an anomaly detector on random noise means the model has no concept of "normal" network traffic (DNS, HTTP, NTP). It will flag legitimate traffic as anomalous purely by chance.
2.  **Zero-Day Vulnerability:** A new installation is effectively blind until the first weekly training cycle (`Mnemosyne`) completes.
3.  **Credibility:** If the system generates 100 false positives in the first hour, the user will uninstall it before it ever learns.

### The Objective
We need a "Foundation Model" — a pre-trained artifact shipped with the appliance. This model should be trained on a generic but representative dataset (like CIC-IoT2023) to provide baseline competence.

### The Plan
1.  **Synthetic Foundation:** Since we cannot train on 30GB of real IoT data in this repo, we will generate a "Synthetic Foundation Model" that approximates the statistical distribution of normal IoT traffic.
2.  **Loader Logic Upgrade:** Refactor `ModelManager` to prioritize:
    1.  Remote Model (Firebase - specialized for this user)
    2.  Local Cached Model (Previous training)
    3.  **Foundation Model (Shipped artifact)**
    4.  Random Fallback (Last resort/Panic mode)
3.  **Configuration:** Expose the foundation model path in `ModelConfig`.

---

## 01. Dev Log: Solving the Cold Start Problem
**Date:** October 26, 2023
**Feature:** Foundation Model Loader

### Problem
As identified in Entry 00, Argus_V starts in a vulnerable state. We needed a way to ship a "good enough" model that works out of the box.

### Options Considered
1.  **Train on Real Data (CIC-IoT2023):**
    *   *Pros:* High accuracy.
    *   *Cons:* Dataset is huge (GBs), impossible to include in repo or CI/CD.
2.  **Rule-Based Fallback:**
    *   *Pros:* Deterministic.
    *   *Cons:* Not "AI", requires maintaining complex rules, defeats the purpose of learning "normal" behavior.
3.  **Synthetic Foundation Model:**
    *   *Pros:* Lightweight, reproducible, better than random.
    *   *Cons:* Approximation of reality.

### Selected Solution
I chose **Option 3**. I created a script `scripts/generate_foundation_model.py` that generates synthetic traffic mimicking DNS, HTTP, NTP, and SSH patterns. It trains an `IsolationForest` on this data and saves the artifacts (`foundation_model.pkl`, `foundation_scaler.pkl`).

I then refactored `ModelManager` to implement a hierarchy of needs:
1.  **Personalized Model** (Remote/Local) - Best.
2.  **Foundation Model** (Shipped) - Good.
3.  **Random Fallback** - Worst case.

### Reflection
This architectural change transforms Argus_V from a "project" to a "product". Users now get immediate value (anomaly detection based on general internet norms) while the system learns their specific environment in the background. The code is modular: if we later get a better foundation model, we just replace the `.pkl` file.
