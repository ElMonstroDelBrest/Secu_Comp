# Side-Channel Analysis : Attaque EMA sur AES-128 (FPGA)

![MATLAB](https://img.shields.io/badge/MATLAB-R2020b+-blue.svg?logo=mathworks)
![Security](https://img.shields.io/badge/Security-SCA%20%7C%20EMA%20%7C%20CPA-red.svg)

Ce dépôt contient les travaux réalisés dans le cadre du **Bureau d'Études (BE) de Sécurité des Composants** à l'**ENSTA Bretagne**. L'objectif est de retrouver la clé secrète d'une implémentation matérielle de l'AES-128 sur FPGA par analyse des fuites électromagnétiques.

## Description

L'attaque cible un chiffrement **AES-128** sur FPGA. À partir de **20 000 traces EM**, les fuites du dernier round sont exploitées pour extraire les 128 bits de la clé.

- **Méthode principale :** CPA (Correlation Power Analysis), corrélation de Pearson
- **Modèle de fuite :** Distance de Hamming — `HD(InvSBox(CTO ⊕ k), ShiftRows(CTO))`
- **Résultat :** 16/16 octets retrouvés, GE = 1 dès 8 000 traces (40 % de la campagne)

## Structure des fichiers

| Fichier | Rôle |
|---|---|
| `extract.m` | Extraction et prétraitement des 20 000 traces CSV, conversion hex→décimal |
| `analyse.m` | Étude académique complète : CPA, DPA ordre 1, Guessing Entropy, figures |
| `dec.m` | Pipeline opérationnel : CPA → vérification → inversion key schedule |
| `decipher_key.m` | Inversion du key schedule AES-128 : K₁₀ → K₀ |
| `verify.m` | Déchiffrement AES-128 complet (GF(2⁸), poly 0x11B) pour validation de clé |
| `mycorr.m` | Corrélation de Pearson vectorisée |
| `rapport.pdf` | Rapport technique complet |
| `squelettes/` | Fonctions fournies : `aide.m`, `keysched2.m` |

## Utilisation

> Les fichiers `.mat` (`L.mat`, `cto_dec.mat`, `key_dec.mat`, `pti_dec.mat`) doivent être présents à la racine (générés par `extract.m`).

**Étude académique (figures + GE) :**
```matlab
run('analyse.m')
```

**Attaque opérationnelle (K₁₀ → K₀) :**
```matlab
run('dec.m')
```

## Prérequis

- MATLAB R2020b ou ultérieur
- Toolbox : Signal Processing (pour `xcorr` si utilisé)

## Auteurs

**GHERASIM George-Daniel** & **BOUE Nathan**
ENSTA Bretagne — Promotion 2025/2026

Encadrant : **Frédéric LE ROY**
