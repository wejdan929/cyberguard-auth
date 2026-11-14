# 🛡️ CyberGuard-Auth v2.1
### Système de Sécurité Adaptatif en Boucle Fermée (Closed-Loop)

## 📌 Présentation du Projet
**CyberGuard-Auth** est un prototype d'authentification et de filtrage de trafic intelligent combinant le Machine Learning (Random Forest) et une architecture d'API moderne (FastAPI). Contrairement aux systèmes de sécurité statiques, ce projet intègre une **boucle de rétroaction adaptative (Feedback Loop)** qui permet d'ajuster dynamiquement les seuils de décision face aux faux positifs et d'enregistrer les corrections dans un historique persistant.

---

## 🏗️ Architecture Technique
1. **Modèle de Machine Learning (`cyberguard_model.pkl`)** : Classificateur Random Forest entraîné pour prédire si une tentative de connexion est légitime (`0`) ou suspecte (`1`), en analysant :
   - `failed_logins` (Échecs de connexion)
   - `request_frequency` (Fréquence des requêtes)
   - `payload_size` (Taille de la charge utile)
   - `ip_reputation` (Score de réputation IP)
2. **API Backend (`main.py`)** : Développée avec **FastAPI**, exposant deux endpoints principaux :
   - `POST /predict` : Évalue le niveau de risque et applique le seuil dynamique.
   - `POST /feedback` : Reçoit les corrections humaines (ex: faux positifs), ajuste le seuil de tolérance et consigne l'événement dans un fichier CSV.
3. **Simulation Automatisée (`test_client.py`)** : Script client simulant un cycle complet de test et d'apprentissage en continu.

---

## 🚀 Guide d'Utilisation

1. **Lancer le serveur FastAPI** :
   ```bash
   uvicorn main:app --reload