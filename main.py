import csv
import os
from datetime import datetime
import joblib
from fastapi import FastAPI
from pydantic import BaseModel

# 1. Charger le modèle Random Forest
model = joblib.load("cyberguard_model.pkl")

# 2. Initialiser l'application FastAPI
app = FastAPI(
    title="CyberGuard-Auth API",
    description="Système de Sécurité Adaptatif en Boucle Fermée avec Persistance",
    version="2.1",
)

# Variable globale pour la boucle adaptative
ADAPTIVE_THRESHOLD = 0.5

# Nom du fichier CSV pour stocker l'historique des feedbacks
CSV_FILE = "feedback_history.csv"


# Initialiser le fichier CSV avec les en-têtes s'il n'existe pas
def init_csv():
  if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as f:
      writer = csv.writer(f)
      writer.writerow([
          "timestamp",
          "failed_logins",
          "request_frequency",
          "payload_size",
          "ip_reputation",
          "actual_status",
          "comment",
      ])


init_csv()


class SecurityData(BaseModel):
  failed_logins: int
  request_frequency: float
  payload_size: int
  ip_reputation: float


class FeedbackData(BaseModel):
  failed_logins: int
  request_frequency: float
  payload_size: int
  ip_reputation: float
  actual_status: int  # 0 = légitime (faux positif), 1 = vraie attaque
  comment: str


@app.get("/")
def read_root():
  return {
      "message": (
          "Bienvenue sur CyberGuard-Auth v2.1 ! Boucle fermée et CSV actifs."
      ),
      "current_adaptive_threshold": ADAPTIVE_THRESHOLD,
  }


@app.post("/predict")
def predict_threat(data: SecurityData):
  features = [[
      data.failed_logins,
      data.request_frequency,
      data.payload_size,
      data.ip_reputation,
  ]]
  prediction = model.predict(features)[0]
  probability = model.predict_proba(features)[0][int(prediction)]

  status = (
      "Attaque détectée !"
      if probability >= ADAPTIVE_THRESHOLD and prediction == 1
      else "Trafic légitime ou sous le seuil de risque."
  )

  return {
      "prediction": int(prediction),
      "status": status,
      "confidence": round(float(probability) * 100, 2),
  }


@app.post("/feedback")
def receive_feedback(feedback: FeedbackData):
  global ADAPTIVE_THRESHOLD

  # 1. Ajustement dynamique du seuil
  if feedback.actual_status == 0:
    ADAPTIVE_THRESHOLD = max(0.3, ADAPTIVE_THRESHOLD - 0.02)
    action_taken = (
        "Faux positif enregistré. Seuil de sécurité assoupli dynamiquement."
    )
  else:
    ADAPTIVE_THRESHOLD = min(0.8, ADAPTIVE_THRESHOLD + 0.01)
    action_taken = "Attaque confirmée. Modèle renforcé."

  # 2. Sauvegarde persistante dans le fichier CSV
  current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  with open(CSV_FILE, mode="a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        current_time,
        feedback.failed_logins,
        feedback.request_frequency,
        feedback.payload_size,
        feedback.ip_reputation,
        feedback.actual_status,
        feedback.comment,
    ])

  return {
      "message": (
          "Feedback pris en compte et enregistré durablement dans le CSV."
      ),
      "action": action_taken,
      "new_adaptive_threshold": round(ADAPTIVE_THRESHOLD, 2),
      "saved_to": CSV_FILE,
  }