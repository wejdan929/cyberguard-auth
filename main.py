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
    version="2.2",
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
          "confidence",
          "comment",
      ])


init_csv()


# Modèles de données Pydantic
class SecurityData(BaseModel):
  failed_logins: int
  request_frequency: float
  payload_size: int
  ip_reputation: float


class FeedbackData(SecurityData):
  actual_status: int  # 0 = légitime (faux positif), 1 = vraie attaque
  comment: str


@app.get("/")
def read_root():
  return {
      "message": (
          "Bienvenue sur CyberGuard-Auth v2.2 ! Boucle fermée intelligente"
          " active."
      ),
      "current_adaptive_threshold": ADAPTIVE_THRESHOLD,
  }


@app.post("/predict")
def predict_traffic(data: SecurityData):
  global ADAPTIVE_THRESHOLD

  # Préparation des features pour le modèle
  features = [[
      data.failed_logins,
      data.request_frequency,
      data.payload_size,
      data.ip_reputation,
  ]]

  # Récupération des probabilités (classe 0 et classe 1)
  probabilities = model.predict_proba(features)[0]
  attack_probability = probabilities[1]  # Probabilité que ce soit une attaque

  # Comparaison avec le seuil adaptatif actuel
  is_attack = int(attack_probability >= ADAPTIVE_THRESHOLD)

  # Format structuré et propre
  return {
      "prediction": is_attack,
      "confidence": round(float(attack_probability), 4),
      "current_adaptive_threshold": ADAPTIVE_THRESHOLD,
      "status": (
          "Alerte : Trafic suspect bloqué"
          if is_attack
          else "Trafic légitime autorisé"
      ),
  }


@app.post("/feedback")
def receive_feedback(feedback: FeedbackData):
  global ADAPTIVE_THRESHOLD

  # Recalcul de la probabilité pour évaluer la "confiance" du modèle lors de l'erreur
  features = [[
      feedback.failed_logins,
      feedback.request_frequency,
      feedback.payload_size,
      feedback.ip_reputation,
  ]]
  probabilities = model.predict_proba(features)[0]
  attack_probability = probabilities[1]

  # Pas d'adaptation intelligent basé sur la confiance du modèle
  confidence_delta = abs(attack_probability - ADAPTIVE_THRESHOLD)
  dynamic_step = max(0.01, round(0.01 + (confidence_delta * 0.05), 4))

  if feedback.actual_status == 0:
    # Faux positif : on baisse le seuil
    ADAPTIVE_THRESHOLD = max(
        0.3, round(ADAPTIVE_THRESHOLD - dynamic_step, 4)
    )
    action_taken = (
        f"Faux positif enregistré. Seuil assoupli dynamiquement de"
        f" -{dynamic_step}."
    )
  else:
    # Vraie attaque : on remonte le seuil
    ADAPTIVE_THRESHOLD = min(
        0.8, round(ADAPTIVE_THRESHOLD + dynamic_step, 4)
    )
    action_taken = (
        f"Attaque confirmée. Seuil durci dynamiquement de +{dynamic_step}."
    )

  # Sauvegarde persistante dans le fichier CSV
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
        round(float(attack_probability), 4),
        feedback.comment,
    ])

  return {
      "message": "Feedback pris en compte et enregistré durablement dans le CSV.",
      "action": action_taken,
      "new_adaptive_threshold": ADAPTIVE_THRESHOLD,
      "saved_to": CSV_FILE,
  }


@app.get("/stats")
def get_statistics():
  if not os.path.exists(CSV_FILE):
    return {
        "total_feedbacks_recorded": 0,
        "false_positives_corrected": 0,
        "true_attacks_confirmed": 0,
        "current_adaptive_threshold": ADAPTIVE_THRESHOLD,
    }

  total_feedbacks = 0
  false_positives = 0
  true_attacks = 0
  latest_incident = None

  with open(CSV_FILE, mode="r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
      total_feedbacks += 1
      if int(row["actual_status"]) == 0:
        false_positives += 1
      else:
        true_attacks += 1
      latest_incident = row

  return {
      "total_feedbacks_recorded": total_feedbacks,
      "false_positives_corrected": false_positives,
      "true_attacks_confirmed": true_attacks,
      "current_adaptive_threshold": ADAPTIVE_THRESHOLD,
      "latest_incident": latest_incident,
  }