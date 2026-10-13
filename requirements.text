# Architecture de Kodda (pour développeurs / IA)

Document de référence en français décrivant l'ensemble du code, pour qu'une autre
personne (ou IA) comprenne immédiatement l'architecture.

## Vue d'ensemble
- **Backend** : FastAPI (`backend/server.py`), base **MongoDB** (driver `motor`), auth **JWT**.
  Toutes les routes sont préfixées par `/api`. Les montants/dates sont normalisés
  (ObjectId → str via `clean()`), dates en ISO UTC.
- **Frontend** : React (`frontend/src`), Tailwind + shadcn/ui, `axios` (`src/lib/api.js`)
  qui ajoute automatiquement le token JWT et pointe sur `REACT_APP_BACKEND_URL`.
- **Scoping par exercice** : presque toutes les entités portent un champ `exercise`
  (année scolaire « 2025-2026 »). Le contexte `ExerciseContext` choisit l'exercice actif
  et le passe en paramètre aux requêtes.

## Collections MongoDB
| Collection | Rôle |
|------------|------|
| `users` | comptes de connexion (email, password bcrypt, role) |
| `contacts` | annuaire ; `types[]` (statuts multiples) + `payer_contact_id` (responsable) |
| `students` | élèves (scopés exercice) ; responsable/payeur intégré |
| `inscriptions` | inscriptions ; `lines[]` (cours+tarif+créneau), `schedule[]` (échéancier) |
| `courses` | cours paramétrés (individuel = modèle ; collectif = groupe à créneau fixe) ; `tariff_id` |
| `teachers` | professeurs pédagogiques ; `employee_id` (lien vers salarié RH) |
| `rooms` | salles |
| `tariffs` | grille tarifaire (category, audience, duration_min, amount) |
| `discounts` | remises paramétrables (label, amount) |
| `employees` | salariés (paie ÉCLAT) |
| `poles` | pôles analytiques |
| `transactions` | écritures recettes/dépenses (scopées exercice, pole_id, method, account_code) |
| `bank_accounts` | comptes (bancaire/caisse/livret) + infos (iban, bic, bank_name, holder, account_number) |
| `transfers` | virements internes entre comptes |
| `bordereaux` | bordereaux de remise espèces/chèques (lines[], total, number) |
| `instruments` / `loans` | parc instruments et prêts |
| `inventory` | stock consommables (manuel) |
| `events` / `event_sales` / `event_tabs` | manifestations, ventes caisse, ardoises ; fond de caisse (cash_open) |
| `receipts` | reçus fiscaux Cerfa |
| `budgets` | budget prévisionnel par exercice |
| `exercises` | exercices comptables (is_current, closed) |
| `ref_lists` | listes/libellés éditables des menus déroulants |
| `settings` | paramètres (clé `association` = infos légales) |

## Flux clés
### Inscription (pilotée par la formule) — `frontend/src/pages/Students.jsx` (InscriptionBuilder)
1. L'élève choisit une **formule** : cursus / théorique seul / pratique collective seule / éveil.
2. Pour un cursus : instrument + **durée** du cours individuel + **public** (déduit de l'âge).
   Le **tarif est résolu automatiquement** dans la grille (`category=cursus` + `duration_min` + `audience`).
3. On attribue le créneau individuel (jour/heure/prof/salle) et éventuellement un groupe théorique/pratique.
4. `build_schedule()` (backend) génère l'**échéancier** selon le mode (annuel/trimestriel/mensuel).

### Échéancier flexible (cotisations) — endpoints `/inscriptions/{id}/...`
- `PUT /pay/{idx}` : encaisse (crée la recette, mémorise `txn_id`).
- `PUT /schedule/{idx}` : édite une échéance (montant, date, moyen, statut) et synchronise la recette.
- `POST /schedule` : ajoute une échéance (régularisations). `DELETE /schedule/{idx}` : supprime (+ recette).

### Caisse manifestations — `frontend/src/pages/Events.jsx`
- Fond de caisse à l'ouverture (`/open-caisse`), ventes ticket/ardoise, clôture avec
  récap par moyen de paiement et écart (`/recap`, `/close`).

### Bordereaux de remise — `frontend/src/pages/Bordereaux.jsx`
- Création d'un bordereau espèces/chèques rattaché à un compte, PDF via `/bordereaux/{id}/pdf`.

## Endpoints principaux (préfixe `/api`)
- Auth : `POST /auth/login`, `GET /auth/me`
- Contacts : `GET/POST/PUT/DELETE /contacts`, `POST /contacts/{id}/create-student`
- Élèves : `GET/POST/PUT/DELETE /students`
- Inscriptions : `POST /inscriptions`, `GET /inscriptions`, échéancier (ci-dessus)
- Pédagogie : `/teachers`, `/rooms`, `/courses`, `/tariffs`, `/discounts`, `/planning`
- Finances : `/transactions`, `/finances/summary`, `/finances/compte-resultat`, `/budget`
- Banque : `/bank-accounts`, `/transfers`, `/bordereaux`
- Caisse : `/events`, `/events/{id}/sales|tabs|open-caisse|recap|close`, `/catalog`
- Divers : `/poles`, `/employees`, `/instruments`, `/loans`, `/inventory`, `/exercises`
- Admin : `/association`, `/receipts`, `/ref-lists`, `/exports/journal`, `/exports/students`

## Conventions importantes
- Ne jamais renvoyer un document Mongo brut : toujours passer par `clean()` (ObjectId → str).
- Les listes déroulantes métier lisent `ref_lists` via `RefListsContext` (optsOf / labelOf).
- Renommer un libellé propage partout ; supprimer une option utilisée est bloqué (HTTP 400).
- Le seed (démarrage) crée l'admin, les exercices, la grille, le catalogue et les listes si absents.
