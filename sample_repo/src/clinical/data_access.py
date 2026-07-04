# Data access layer - reads/writes clinical records.
# NOTE: no audit logging implemented here yet.
def get_record(patient_id):
    return db.query(patient_id)
