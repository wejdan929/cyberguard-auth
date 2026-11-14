import os
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import joblib

app = FastAPI(
    title="CyberGuard-Auth",
    description=(
        "API de sécurité adaptative en boucle fermée avec Random Forest, seuil"
        " dynamique et persistance CSV."
    ),
    version="2.2",
)

# Chargement du modèle Random Forest pré-entraîné
model = joblib.load("cyberguard_model.pkl")

# Variable globale pour le seuil adaptatif en mémoire vive (RAM)
ADAPTIVE_THRESHOLD = 0.5

# Fichier CSV pour la persistance durable des feedbacks
FEEDBACK_CSV = "feedback_history.csv"

# Initialisation du fichier CSV s'il n'existe pas
if not os.path.exists(FEEDBACK_CSV):
  df_init = pd.DataFrame(
      columns=[
          "timestamp",
          "failed_logins",
          "request_frequency",
          "payload_size",
          "ip_reputation",
          "predicted_label",
          "actual_status",
          "confidence",
          "comment",
      ]
  )
  df_init.to_csv(FEEDBACK_CSV, index=False)


class TrafficInput(BaseModel):
  failed_logins: int = Field(
      ..., description="Nombre d'échecs de connexion récents"
  )
  request_frequency: float = Field(
      ..., description="Fréquence des requêtes par minute"
  )
  payload_size: int = Field(
      ..., description="Taille de la charge utile en octets"
  )
  ip_reputation: float = Field(
      ..., description="Score de réputation de l'IP (0 à 1)"
  )


class FeedbackInput(TrafficInput):
  actual_status: int = Field(
      ..., description="0 = Trafic légitime (Faux positif), 1 = Vraie attaque"
  )
  comment: str = Field(..., description="Commentaire explicatif de l'admin")


@app.get("/")
def home():
  return {
      "message": (
          "Bienvenue sur CyberGuard-Auth v2.2 ! Boucle fermée intelligente et"
          " CSV actifs."
      ),
      "current_adaptive_threshold": ADAPTIVE_THRESHOLD,
  }


@app.post("/predict")
def predict_traffic(data: TrafficInput):
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

  return {
      "prediction": is_attack,  # 1 = Attaque, 0 = Normal
      "attack_probability": round(float(attack_probability), 4),
      "current_adaptive_threshold": ADAPTIVE_THRESHOLD,
      "status": (
          "Alerte : Trafic suspect bloqué"
          if is_attack
          else "Trafic légitime autorisé"
      ),
  }


@app.post("/feedback")
def receive_feedback(feedback: FeedbackInput):
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

  # IDÉE 1 : Pas d'adaptation intelligent basé sur la confiance du modèle
  # Plus le modèle était sûr de lui dans l'erreur, plus la correction est proportionnelle
  confidence_delta = abs(attack_probability - ADAPTIVE_THRESHOLD)
  dynamic_step = max(0.01, round(0.01 + (confidence_delta * 0.05), 4))

  action_msg = ""
  if feedback.actual_status == 0:
    # Faux positif : on baisse le seuil pour devenir plus tolérant
    ADAPTIVE_THRESHOLD = max(
        0.3, round(ADAPTIVE_THRESHOLD - dynamic_step, 4)
    )
    action_msg = (
        f"Faux positif enregistré. Seuil assoupli de manière dynamique de"
        f" -{dynamic_step}."
    )
  else:
    # Vraie attaque : on remonte le seuil prudemment pour durcir la sécurité
    ADAPTIVE_THRESHOLD = min(
        0.8, round(ADAPTIVE_THRESHOLD + dynamic_step, 4)
    )
    action_msg = (
        f"Attaque confirmée. Seuil durci de manière dynamique de"
        f" +{dynamic_step}."
    )

  # Enregistrement persistant dans le fichier CSV
  new_row = pd.DataFrame([{
      "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
      "failed_logins": feedback.failed_logins,
      "request_frequency": feedback.request_frequency,
      "payload_size": feedback.payload_size,
      "ip_reputation": feedback.ip_reputation,
      "predicted_label": int(attack_probability >= ADAPTIVE_THRESHOLD),
      "actual_status": feedback.actual_status,
      "confidence": round(float(attack_probability), 4),
      "comment": feedback.comment,
  }])

  new_row.to_csv(FEEDBACK_CSV, mode="a", header=False, index=False)

  return {
      "message": "Feedback pris en compte et enregistré durablement dans le CSV.",
      "action": action_msg,
      "new_adaptive_threshold": ADAPTIVE_THRESHOLD,
      "saved_to": FEEDBACK_CSV,
  }


# IDÉE 2 : Endpoint de statistiques (/stats) pour analyser le fichier CSV en direct
@app.get("/stats")
def get_system_stats():
  if not os.path.exists(FEEDBACK_CSV):
    return {"total_feedbacks": 0, "false_positives": 0, "true_attacks": 0}

  df = pd.read_csv(FEEDBACK_CSV)
  total_feedbacks = len(df)

  if total_feedbacks == 0:
    return {"total_feedbacks": 0, "false_positives": 0, "true_attacks": 0}

  false_positives = int((df["actual_status"] == 0).sum())
  true_attacks = int((df["actual_status"] == 1).sum())

  return {
      "total_feedbacks_recorded": total_feedbacks,
      "false_positives_corrected": false_positives,
      "true_attacks_confirmed": true_attacks,
      "current_adaptive_threshold": ADAPTIVE_THRESHOLD,
      "latest_incident": (
          df.iloc[-1].to_dict() if total_feedbacks > 0 else None
      ),
  }