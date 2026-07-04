# Clinical decision module - produces diagnostic suggestions from patient data.
# Handles PHI: patient_id, diagnosis codes, lab results.
def evaluate_patient(patient_record):
    phi = patient_record["phi"]  # sensitive
    return {"diagnosis": "...", "confidence": 0.9}
