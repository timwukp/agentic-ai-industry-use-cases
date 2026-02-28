import React, { useState } from 'react'
import { AlertTriangle, Shield, ChevronDown, ChevronRight, Heart, Activity, Zap } from 'lucide-react'

/* ── Drug Interaction Data ─────────────────────────────────────── */

interface DrugInteraction {
  drug1: string
  drug2: string
  severity: 'Major' | 'Moderate' | 'Minor'
  description: string
  recommendation: string
}

const drugInteractions: DrugInteraction[] = [
  { drug1: 'Warfarin', drug2: 'Aspirin', severity: 'Major', description: 'Increased risk of bleeding. Concurrent use significantly elevates hemorrhagic risk, particularly GI bleeding.', recommendation: 'Avoid combination unless specifically indicated. Monitor INR closely if co-prescribed. Consider PPI for GI protection.' },
  { drug1: 'Warfarin', drug2: 'Lisinopril', severity: 'Moderate', description: 'ACE inhibitors may increase the anticoagulant effect of warfarin. Potential for elevated INR values.', recommendation: 'Monitor INR more frequently when initiating, adjusting, or discontinuing lisinopril. Adjust warfarin dose as needed.' },
  { drug1: 'Metformin', drug2: 'Contrast Dye', severity: 'Major', description: 'Risk of lactic acidosis. Iodinated contrast agents may cause acute kidney injury, impairing metformin clearance.', recommendation: 'Hold metformin 48 hours before and after contrast procedures. Check renal function before resuming.' },
  { drug1: 'Lisinopril', drug2: 'Potassium Supplements', severity: 'Moderate', description: 'ACE inhibitors reduce aldosterone secretion, leading to potassium retention. Concurrent supplementation may cause hyperkalemia.', recommendation: 'Monitor serum potassium levels regularly. Avoid potassium supplements unless hypokalemia is documented.' },
  { drug1: 'Amiodarone', drug2: 'Simvastatin', severity: 'Major', description: 'Amiodarone inhibits CYP3A4, significantly increasing simvastatin levels. Risk of rhabdomyolysis.', recommendation: 'Do not exceed simvastatin 20mg daily with amiodarone. Consider switching to pravastatin or rosuvastatin.' },
  { drug1: 'Fluoxetine', drug2: 'Tramadol', severity: 'Moderate', description: 'Both agents increase serotonin levels. Risk of serotonin syndrome with concurrent use.', recommendation: 'Use with caution. Monitor for signs of serotonin syndrome: agitation, hyperthermia, tachycardia, tremor.' },
]

const severityColors: Record<string, string> = {
  'Major': 'bg-red-900/30 text-red-400 border-red-800/50',
  'Moderate': 'bg-orange-900/30 text-orange-400 border-orange-800/50',
  'Minor': 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50',
}

const severityDotColors: Record<string, string> = {
  'Major': 'bg-red-500',
  'Moderate': 'bg-orange-500',
  'Minor': 'bg-yellow-500',
}

/* ── Risk Score Data ───────────────────────────────────────────── */

interface RiskScore {
  name: string
  category: string
  score: number
  maxScore: number
  unit: string
  level: string
  color: string
  detail: string
  icon: React.ElementType
}

const riskScores: RiskScore[] = [
  { name: 'ASCVD Risk Score', category: 'Cardiovascular', score: 18.4, maxScore: 100, unit: '%', level: 'Borderline High', color: '#f59e0b', detail: '10-year atherosclerotic cardiovascular disease risk', icon: Heart },
  { name: 'HbA1c Trend', category: 'Diabetes', score: 7.2, maxScore: 14, unit: '%', level: 'Above Target', color: '#f97316', detail: 'Glycated hemoglobin, target < 7.0% for most adults', icon: Activity },
  { name: 'Morse Fall Scale', category: 'Falls Risk', score: 55, maxScore: 125, unit: 'pts', level: 'High Risk', color: '#ef4444', detail: 'Score >= 45 indicates high fall risk, implement precautions', icon: Zap },
]

/* ── Clinical Guidelines Data ──────────────────────────────────── */

interface Guideline {
  condition: string
  summary: string
  keyPoints: string[]
  source: string
}

const guidelines: Guideline[] = [
  {
    condition: 'Type 2 Diabetes Management',
    summary: 'ADA Standards of Care recommend individualized HbA1c targets with metformin as first-line therapy.',
    keyPoints: [
      'HbA1c target < 7% for most adults; individualize for elderly or those with comorbidities',
      'Metformin remains first-line pharmacotherapy unless contraindicated',
      'Add GLP-1 RA or SGLT2 inhibitor for patients with established ASCVD or CKD',
      'Annual screening: retinal exam, foot exam, urine albumin, lipid panel',
      'Blood pressure target < 130/80 mmHg for patients with diabetes',
    ],
    source: 'ADA Standards of Care 2026',
  },
  {
    condition: 'Hypertension (ACC/AHA)',
    summary: 'Blood pressure target < 130/80 mmHg for most adults. Lifestyle modifications are foundational.',
    keyPoints: [
      'Stage 1: BP 130-139/80-89 - lifestyle modifications, consider medication if ASCVD risk >= 10%',
      'Stage 2: BP >= 140/90 - initiate medication plus lifestyle modifications',
      'First-line agents: ACE inhibitor, ARB, calcium channel blocker, or thiazide diuretic',
      'Dual therapy recommended for Stage 2 or BP > 20/10 mmHg above target',
      'Home blood pressure monitoring recommended for all patients with hypertension',
    ],
    source: 'ACC/AHA Guidelines 2025',
  },
  {
    condition: 'Heart Failure (ACC/AHA/HFSA)',
    summary: 'GDMT includes ARNI, beta-blocker, MRA, and SGLT2 inhibitor for HFrEF patients.',
    keyPoints: [
      'Quadruple therapy for HFrEF: ARNI (or ACEi/ARB), beta-blocker, MRA, SGLT2 inhibitor',
      'Titrate medications to target doses as tolerated over 3-6 months',
      'SGLT2 inhibitors now recommended for HFpEF as well (Class 2a)',
      'Cardiac rehabilitation recommended for all stable HF patients',
      'Reassess LVEF at 3-6 months after initiating GDMT',
    ],
    source: 'ACC/AHA/HFSA Guidelines 2025',
  },
  {
    condition: 'COPD (GOLD Report)',
    summary: 'Classify by symptoms and exacerbation risk. Inhaled bronchodilators are first-line for symptom relief.',
    keyPoints: [
      'Group A: PRN short-acting bronchodilator (SABA or SAMA)',
      'Group B: Long-acting bronchodilator (LABA or LAMA)',
      'Group E: LABA+LAMA; consider ICS if eosinophils >= 300 cells/uL',
      'Annual influenza and pneumococcal vaccination recommended for all patients',
      'Pulmonary rehabilitation improves exercise capacity and quality of life',
    ],
    source: 'GOLD Report 2026',
  },
]

/* ── Triage Assessment Data ────────────────────────────────────── */

interface TriageCase {
  symptoms: string
  urgency: 'Emergency' | 'Urgent' | 'Semi-Urgent' | 'Routine'
  assessment: string
  recommendation: string
}

const triageCases: TriageCase[] = [
  { symptoms: 'Chest pain, diaphoresis, radiating to left arm', urgency: 'Emergency', assessment: 'Possible acute coronary syndrome. High suspicion for STEMI/NSTEMI.', recommendation: 'Activate Code STEMI protocol. 12-lead ECG within 10 minutes. ASA 325mg. Troponin STAT.' },
  { symptoms: 'Sudden severe headache, neck stiffness, photophobia', urgency: 'Emergency', assessment: 'Possible subarachnoid hemorrhage or meningitis. Requires emergent evaluation.', recommendation: 'Immediate CT head without contrast. If negative, lumbar puncture. Neurology consult.' },
  { symptoms: 'Fever 101.5F, productive cough x 5 days, dyspnea', urgency: 'Urgent', assessment: 'Likely community-acquired pneumonia. Moderate severity based on symptoms and duration.', recommendation: 'Chest X-ray, CBC, BMP, blood cultures. Start empiric antibiotics. Assess CURB-65 score.' },
  { symptoms: 'Ankle swelling and pain after fall, can bear weight', urgency: 'Semi-Urgent', assessment: 'Possible ankle sprain vs. fracture. Ottawa ankle rules suggest imaging if bony tenderness present.', recommendation: 'X-ray ankle AP/lateral/mortise. RICE protocol. Reassess in 48-72 hours if no fracture.' },
  { symptoms: 'Mild sore throat, low-grade fever, no dysphagia', urgency: 'Routine', assessment: 'Likely viral upper respiratory infection. Low acuity presentation.', recommendation: 'Rapid strep test if Centor criteria >= 2. Supportive care. Return if worsening in 5-7 days.' },
]

const urgencyColors: Record<string, { text: string; bg: string; border: string }> = {
  'Emergency': { text: 'text-red-400', bg: 'bg-red-900/20', border: 'border-red-800/40' },
  'Urgent': { text: 'text-orange-400', bg: 'bg-orange-900/20', border: 'border-orange-800/40' },
  'Semi-Urgent': { text: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-800/40' },
  'Routine': { text: 'text-green-400', bg: 'bg-green-900/20', border: 'border-green-800/40' },
}

export default function ClinicalSupport() {
  const [expandedGuideline, setExpandedGuideline] = useState<number | null>(0)

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      <h2 className="text-xl font-bold text-white">Clinical Decision Support</h2>

      {/* Drug Interaction Checker */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
          <Shield className="w-4 h-4 text-rose-400" />
          <h3 className="text-sm font-medium text-gray-400">Drug Interaction Checker</h3>
          <span className="ml-auto text-xs text-gray-500">{drugInteractions.length} interactions found</span>
        </div>
        <div className="divide-y divide-gray-800/50">
          {drugInteractions.map((interaction, i) => (
            <div key={i} className="px-6 py-4 hover:bg-gray-800/30">
              <div className="flex items-start gap-3">
                <div className={`w-2 h-2 rounded-full mt-2 flex-shrink-0 ${severityDotColors[interaction.severity]}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-gray-200">{interaction.drug1}</span>
                      <span className="text-xs text-gray-500">+</span>
                      <span className="text-sm font-medium text-gray-200">{interaction.drug2}</span>
                    </div>
                    <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium border ${severityColors[interaction.severity]}`}>
                      {interaction.severity}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 mb-1">{interaction.description}</p>
                  <p className="text-xs text-rose-400/80">
                    <span className="text-gray-500">Recommendation: </span>{interaction.recommendation}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Risk Score Cards + Triage */}
      <div className="grid grid-cols-2 gap-6">
        {/* Risk Score Cards */}
        <div className="space-y-4">
          <h3 className="text-sm font-medium text-gray-400">Clinical Risk Scores</h3>
          {riskScores.map((risk) => {
            const RiskIcon = risk.icon
            const pct = (risk.score / risk.maxScore) * 100
            return (
              <div key={risk.name} className="bg-gray-900 rounded-xl p-5 border border-gray-800">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <RiskIcon className="w-4 h-4" style={{ color: risk.color }} />
                    <span className="text-sm font-medium text-gray-300">{risk.name}</span>
                  </div>
                  <span className="text-xs px-2 py-0.5 rounded" style={{ color: risk.color, background: `${risk.color}20`, border: `1px solid ${risk.color}40` }}>
                    {risk.level}
                  </span>
                </div>
                <div className="flex items-end gap-2 mb-2">
                  <span className="text-3xl font-bold text-white">{risk.score}</span>
                  <span className="text-sm text-gray-500 mb-1">{risk.unit}</span>
                </div>
                <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden mb-2">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(pct, 100)}%`, background: risk.color }}
                  />
                </div>
                <p className="text-xs text-gray-500">{risk.detail}</p>
              </div>
            )
          })}
        </div>

        {/* Triage Assessment */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-medium text-gray-400">Triage Assessment Queue</h3>
          </div>
          <div className="divide-y divide-gray-800/50">
            {triageCases.map((triage, i) => {
              const style = urgencyColors[triage.urgency]
              return (
                <div key={i} className="px-6 py-4 hover:bg-gray-800/30">
                  <div className="flex items-start gap-3">
                    <div className={`px-2 py-1 rounded text-xs font-bold ${style.text} ${style.bg} border ${style.border} flex-shrink-0 mt-0.5`}>
                      {triage.urgency}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-gray-200 mb-1">{triage.symptoms}</div>
                      <p className="text-xs text-gray-400 mb-1">{triage.assessment}</p>
                      <p className="text-xs text-rose-400/80">
                        <span className="text-gray-500">Action: </span>{triage.recommendation}
                      </p>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Clinical Guidelines Quick Reference */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-400">Clinical Guidelines Quick Reference</h3>
        </div>
        <div className="divide-y divide-gray-800/50">
          {guidelines.map((guideline, i) => (
            <div key={i} className="hover:bg-gray-800/30">
              <button
                onClick={() => setExpandedGuideline(expandedGuideline === i ? null : i)}
                className="w-full px-6 py-4 flex items-center justify-between text-left"
              >
                <div>
                  <div className="text-sm font-medium text-gray-200">{guideline.condition}</div>
                  <div className="text-xs text-gray-500 mt-0.5">{guideline.source}</div>
                </div>
                {expandedGuideline === i ? (
                  <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
                )}
              </button>
              {expandedGuideline === i && (
                <div className="px-6 pb-4">
                  <p className="text-sm text-gray-300 mb-3">{guideline.summary}</p>
                  <ul className="space-y-2">
                    {guideline.keyPoints.map((point, j) => (
                      <li key={j} className="flex items-start gap-2 text-xs text-gray-400">
                        <span className="w-1.5 h-1.5 bg-rose-500 rounded-full mt-1.5 flex-shrink-0" />
                        {point}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
