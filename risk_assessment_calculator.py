#!/usr/bin/env python3
"""
Risk Assessment Calculator per E-commerce di Abbigliamento
Implementa il calcolo del fattore di rischio basato su metodologie NIST, PCI DSS e GDPR
 
Autore: Andrea Palamà
"""

import json
import datetime
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from enum import Enum

class RiskLevel(Enum):
    """Livelli di rischio definiti"""
    MOLTO_BASSO = 1
    BASSO = 2
    MEDIO = 3
    ALTO = 4
    CRITICO = 5

class AssetType(Enum):
    """Tipi di asset aziendali"""
    SITO_WEB = "Sito Web E-commerce"
    DATABASE_CLIENTI = "Database Clienti"
    SISTEMA_PAGAMENTI = "Sistema di Pagamento"
    INFRASTRUTTURA_IT = "Infrastruttura IT"
    DATI_CARTE_CREDITO = "Dati Carte di Credito"

class ThreatCategory(Enum):
    """Categorie di minacce"""
    CYBER_ATTACK = "Attacco Informatico"
    HUMAN_ERROR = "Errore Umano"
    SYSTEM_FAILURE = "Guasto del Sistema"
    NATURAL_DISASTER = "Disastro Naturale"
    INSIDER_THREAT = "Minaccia Interna"

@dataclass
class Vulnerability:
    """Rappresenta una vulnerabilità"""
    name: str
    description: str
    owasp_category: str
    exploitability: int  # 1-5 scala
    detection_difficulty: int  # 1-5 scala

@dataclass
class Asset:
    """Rappresenta un asset aziendale"""
    name: str
    asset_type: AssetType
    description: str
    business_value: int  # 1-5 scala
    data_sensitivity: int  # 1-5 scala

@dataclass
class Threat:
    """Rappresenta una minaccia"""
    name: str
    category: ThreatCategory
    description: str
    frequency: int  # 1-5 scala (probabilità)
    sophistication: int  # 1-5 scala

@dataclass
class RiskScenario:
    """Rappresenta uno scenario di rischio"""
    id: str
    asset: Asset
    threat: Threat
    vulnerability: Vulnerability
    probability: float
    impact: float
    risk_score: float
    risk_level: str
    mitigation_measures: List[str]
    compliance_impact: Dict[str, str]  # PCI DSS, GDPR, etc.

class RiskAssessmentCalculator:
    """Calcolatore per la valutazione del rischio"""
    
    def __init__(self):
        self.assets = []
        self.threats = []
        self.vulnerabilities = []
        self.risk_scenarios = []
        self._initialize_default_assets()
        self._initialize_default_threats()
        self._initialize_default_vulnerabilities()
    
    def _initialize_default_assets(self):
        self.assets = [
            Asset("Sito Web E-commerce", AssetType.SITO_WEB, 
                  "Piattaforma online per vendita abbigliamento", 5, 3),
            Asset("Database Clienti", AssetType.DATABASE_CLIENTI, 
                  "Database contenente dati personali dei clienti", 4, 5),
            Asset("Sistema Pagamenti", AssetType.SISTEMA_PAGAMENTI, 
                  "Sistema per elaborazione pagamenti con carte di credito", 5, 5),
            Asset("Infrastruttura Server", AssetType.INFRASTRUTTURA_IT, 
                  "Server e infrastruttura di supporto", 4, 3),
            Asset("Archivio Dati Carte", AssetType.DATI_CARTE_CREDITO, 
                  "Dati sensibili delle carte di credito", 5, 5)
        ]
    
    def _initialize_default_threats(self):
        self.threats = [
            Threat("SQL Injection", ThreatCategory.CYBER_ATTACK, 
                   "Attacco di iniezione SQL per accesso non autorizzato ai dati", 4, 3),
            Threat("Cross-Site Scripting (XSS)", ThreatCategory.CYBER_ATTACK, 
                   "Iniezione di script malevoli nel sito web", 4, 2),
            Threat("Data Breach", ThreatCategory.CYBER_ATTACK, 
                   "Violazione dei dati con accesso non autorizzato", 3, 4),
            Threat("DDoS Attack", ThreatCategory.CYBER_ATTACK, 
                   "Attacco di negazione del servizio distribuito", 3, 2),
            Threat("Phishing", ThreatCategory.CYBER_ATTACK, 
                   "Attacco di phishing per rubare credenziali", 4, 2),
            Threat("Errore Configurazione", ThreatCategory.HUMAN_ERROR, 
                   "Errore umano nella configurazione dei sistemi", 3, 1),
            Threat("Guasto Hardware", ThreatCategory.SYSTEM_FAILURE, 
                   "Guasto dell'hardware dei server", 2, 1)
        ]
    
    def _initialize_default_vulnerabilities(self):
        self.vulnerabilities = [
            Vulnerability("Broken Access Control", "Controlli di accesso inadeguati o mancanti", "A01:2021", 4, 3),
            Vulnerability("Cryptographic Failures", "Fallimenti nella crittografia dei dati sensibili", "A02:2021", 3, 4),
            Vulnerability("Injection", "Vulnerabilità di iniezione (SQL, NoSQL, OS)", "A03:2021", 4, 3),
            Vulnerability("Insecure Design", "Progettazione insicura dell'applicazione", "A04:2021", 3, 4),
            Vulnerability("Security Misconfiguration", "Configurazioni di sicurezza errate", "A05:2021", 4, 2),
            Vulnerability("Vulnerable Components", "Uso di componenti con vulnerabilità note", "A06:2021", 3, 3),
            Vulnerability("Authentication Failures", "Fallimenti nell'autenticazione e gestione sessioni", "A07:2021", 4, 3)
        ]
    
    def calculate_probability(self, threat: Threat, vulnerability: Vulnerability) -> float:
        raw_probability = (threat.frequency + vulnerability.exploitability) / 2
        return min(5.0, max(1.0, raw_probability))
    
    def calculate_impact(self, asset: Asset, threat: Threat) -> float:
        base_impact = (asset.business_value + asset.data_sensitivity) / 2
        threat_multiplier = 1 + (threat.sophistication - 1) * 0.2
        impact = base_impact * threat_multiplier
        return min(5.0, max(1.0, impact))
    
    def calculate_risk_score(self, probability: float, impact: float) -> float:
        return probability * impact
    
    def determine_risk_level(self, risk_score: float) -> str:
        if risk_score <= 5.0:
            return "Molto Basso"
        elif risk_score <= 10.0:
            return "Basso"
        elif risk_score <= 15.0:
            return "Medio"
        elif risk_score <= 20.0:
            return "Alto"
        else:
            return "Critico"
    
    def get_mitigation_measures(self, vulnerability: Vulnerability, risk_level: str) -> List[str]:
        measures = {
            "Broken Access Control": [
                "Implementare controlli di accesso basati sui ruoli (RBAC)",
                "Utilizzare il principio del minimo privilegio",
                "Implementare autenticazione multi-fattore (MFA)",
                "Condurre audit regolari degli accessi"
            ],
            "Cryptographic Failures": [
                "Implementare crittografia forte per dati in transito e a riposo",
                "Utilizzare algoritmi crittografici aggiornati (AES-256, TLS 1.3)",
                "Implementare gestione sicura delle chiavi crittografiche",
                "Condurre audit delle implementazioni crittografiche"
            ],
            "Injection": [
                "Utilizzare query parametrizzate e prepared statements",
                "Implementare validazione rigorosa dell'input",
                "Utilizzare Web Application Firewall (WAF)",
                "Condurre test di penetrazione regolari"
            ],
            "Insecure Design": [
                "Implementare Security by Design nei processi di sviluppo",
                "Condurre threat modeling durante la progettazione",
                "Implementare controlli di sicurezza a più livelli",
                "Condurre review di sicurezza del codice"
            ],
            "Security Misconfiguration": [
                "Implementare configurazioni di sicurezza standardizzate",
                "Utilizzare strumenti di gestione della configurazione",
                "Condurre scan di vulnerabilità regolari",
                "Implementare monitoraggio della configurazione"
            ],
            "Vulnerable Components": [
                "Mantenere inventario aggiornato dei componenti software",
                "Implementare processo di patch management",
                "Utilizzare strumenti di scansione delle vulnerabilità",
                "Monitorare advisory di sicurezza"
            ],
            "Authentication Failures": [
                "Implementare politiche di password robuste",
                "Utilizzare autenticazione multi-fattore",
                "Implementare gestione sicura delle sessioni",
                "Monitorare tentativi di accesso sospetti"
            ]
        }
        
        base_measures = measures.get(vulnerability.name, ["Implementare controlli di sicurezza generici"])
        if risk_level in ["Alto", "Critico"]:
            base_measures.extend([
                "Implementare monitoraggio 24/7",
                "Condurre assessment di sicurezza immediato",
                "Considerare l'implementazione di controlli compensativi"
            ])
        return base_measures
    
    def get_compliance_impact(self, asset: Asset, vulnerability: Vulnerability) -> Dict[str, str]:
        impact = {}
        if asset.asset_type in [AssetType.SISTEMA_PAGAMENTI, AssetType.DATI_CARTE_CREDITO]:
            if vulnerability.name in ["Broken Access Control", "Cryptographic Failures", "Injection"]:
                impact["PCI DSS"] = "Alto - Possibili violazioni dei requisiti 3, 6, 7, 8"
            else:
                impact["PCI DSS"] = "Medio - Possibili violazioni dei requisiti generali"
        if asset.asset_type in [AssetType.DATABASE_CLIENTI, AssetType.SITO_WEB]:
            if vulnerability.name in ["Broken Access Control", "Cryptographic Failures"]:
                impact["GDPR"] = "Alto - Possibili violazioni Art. 32"
            else:
                impact["GDPR"] = "Medio - Possibili violazioni principi generali"
        impact["Misure Minime AgID"] = "Medio - Possibili violazioni controlli di sicurezza"
        return impact
    
    def generate_risk_scenarios(self) -> List[RiskScenario]:
        scenarios = []
        scenario_id = 1
        for asset in self.assets:
            for threat in self.threats:
                for vulnerability in self.vulnerabilities:
                    probability = self.calculate_probability(threat, vulnerability)
                    impact = self.calculate_impact(asset, threat)
                    risk_score = self.calculate_risk_score(probability, impact)
                    risk_level = self.determine_risk_level(risk_score)
                    mitigation_measures = self.get_mitigation_measures(vulnerability, risk_level)
                    compliance_impact = self.get_compliance_impact(asset, vulnerability)
                    scenario = RiskScenario(
                        id=f"RISK-{scenario_id:03d}",
                        asset=asset,
                        threat=threat,
                        vulnerability=vulnerability,
                        probability=probability,
                        impact=impact,
                        risk_score=risk_score,
                        risk_level=risk_level,
                        mitigation_measures=mitigation_measures,
                        compliance_impact=compliance_impact
                    )
                    scenarios.append(scenario)
                    scenario_id += 1
        scenarios.sort(key=lambda x: x.risk_score, reverse=True)
        self.risk_scenarios = scenarios
        return scenarios
    
    def export_to_json(self, filename: str = None) -> str:
        if filename is None:
            filename = f"risk_assessment_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        export_data = {
            "metadata": {
                "generated_at": datetime.datetime.now().isoformat(),
                "company_type": "E-commerce Abbigliamento",
                "assessment_methodology": "NIST CSF + PCI DSS + GDPR",
                "total_scenarios": len(self.risk_scenarios)
            },
            "risk_summary": {
                "critico": len([s for s in self.risk_scenarios if s.risk_level == "Critico"]),
                "alto": len([s for s in self.risk_scenarios if s.risk_level == "Alto"]),
                "medio": len([s for s in self.risk_scenarios if s.risk_level == "Medio"]),
                "basso": len([s for s in self.risk_scenarios if s.risk_level == "Basso"]),
                "molto_basso": len([s for s in self.risk_scenarios if s.risk_level == "Molto Basso"])
            },
            "top_risks": [
                {
                    "id": scenario.id,
                    "asset": scenario.asset.name,
                    "threat": scenario.threat.name,
                    "vulnerability": scenario.vulnerability.name,
                    "probability": scenario.probability,
                    "impact": scenario.impact,
                    "risk_score": scenario.risk_score,
                    "risk_level": scenario.risk_level,
                    "mitigation_measures": scenario.mitigation_measures,
                    "compliance_impact": scenario.compliance_impact
                }
                for scenario in self.risk_scenarios[:20]
            ]
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
        return filename
    
    def generate_summary_report(self) -> str:
        if not self.risk_scenarios:
            self.generate_risk_scenarios()
        report = []
        report.append("=" * 80)
        report.append("RAPPORTO DI VALUTAZIONE DEL RISCHIO - E-COMMERCE ABBIGLIAMENTO")
        report.append("=" * 80)
        report.append(f"Data generazione: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        report.append(f"Metodologia: NIST Cybersecurity Framework + PCI DSS + GDPR")
        report.append(f"Totale scenari valutati: {len(self.risk_scenarios)}")
        report.append("")
        risk_counts = {}
        for scenario in self.risk_scenarios:
            level = scenario.risk_level
            risk_counts[level] = risk_counts.get(level, 0) + 1
        report.append("RIEPILOGO PER LIVELLO DI RISCHIO:")
        report.append("-" * 40)
        for level in ["Critico", "Alto", "Medio", "Basso", "Molto Basso"]:
            count = risk_counts.get(level, 0)
            percentage = (count / len(self.risk_scenarios)) * 100
            report.append(f"{level:12}: {count:3d} scenari ({percentage:5.1f}%)")
        return "\n".join(report)

def main():
    print("Avvio Calcolatore di Valutazione del Rischio per E-commerce Abbigliamento")
    calculator = RiskAssessmentCalculator()
    scenarios = calculator.generate_risk_scenarios()
    json_file = calculator.export_to_json()
    print(f"Risultati esportati in: {json_file}")
    summary = calculator.generate_summary_report()
    report_file = f"risk_assessment_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(summary)
    print(f"Report riassuntivo salvato in: {report_file}")
    print("\nAnteprima risultati:")
    print(summary[:2000] + "..." if len(summary) > 2000 else summary)

if __name__ == "__main__":
    main()
