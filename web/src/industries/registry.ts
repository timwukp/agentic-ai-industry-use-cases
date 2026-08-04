import { createElement, type ComponentType } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  Building2,
  Factory,
  HeartPulse,
  LineChart,
  ShieldCheck,
  ShoppingCart,
} from 'lucide-react'
import PlaceholderDashboard from './PlaceholderDashboard'
import FinanceDashboard from './finance/FinanceDashboard'
import HealthcareDashboard from './healthcare/HealthcareDashboard'

export interface IndustryModule {
  id: string
  name: string
  icon: LucideIcon
  /** Tailwind text-color class used as the industry accent. */
  themeColor: string
  description: string
  enabled: boolean
  Dashboard: ComponentType
  /** Harness ARN override; defaults to config.harnessArn (finance). */
  harnessArn?: string
}

function placeholder(
  name: string,
  description: string,
  icon: LucideIcon,
  accentClass: string,
  chatLive = false,
): ComponentType {
  return function ComingSoon() {
    return createElement(PlaceholderDashboard, {
      name,
      description,
      icon,
      accentClass,
      chatLive,
    })
  }
}

export const industries: IndustryModule[] = [
  {
    id: 'finance',
    name: 'Finance & Trading',
    icon: LineChart,
    themeColor: 'text-blue-400',
    description:
      'Portfolio analytics, market overview and order flow with an AI trading assistant.',
    enabled: true,
    Dashboard: FinanceDashboard,
  },
  {
    id: 'healthcare-medical',
    name: 'Healthcare & Medical',
    icon: HeartPulse,
    themeColor: 'text-rose-400',
    description:
      'Drug interactions, clinical guidelines, scheduling and population health with an AI medical records assistant.',
    enabled: Boolean(import.meta.env.VITE_HARNESS_ARN_HEALTHCARE),
    harnessArn: import.meta.env.VITE_HARNESS_ARN_HEALTHCARE as string | undefined,
    Dashboard: HealthcareDashboard,
  },
  {
    id: 'insurance-claims',
    name: 'Insurance Claims',
    icon: ShieldCheck,
    themeColor: 'text-indigo-400',
    description:
      'Claims intake, document analysis, fraud signals and settlement recommendations.',
    enabled: Boolean(import.meta.env.VITE_HARNESS_ARN_INSURANCE),
    harnessArn: import.meta.env.VITE_HARNESS_ARN_INSURANCE as string | undefined,
    Dashboard: placeholder(
      'Insurance Claims',
      'Claims intake, document analysis, fraud signals and settlement recommendations.',
      ShieldCheck,
      'text-indigo-400',
      Boolean(import.meta.env.VITE_HARNESS_ARN_INSURANCE),
    ),
  },
  {
    id: 'retail-inventory',
    name: 'Retail Inventory',
    icon: ShoppingCart,
    themeColor: 'text-emerald-400',
    description:
      'Demand forecasting, stock optimization and automated replenishment workflows.',
    enabled: Boolean(import.meta.env.VITE_HARNESS_ARN_RETAIL),
    harnessArn: import.meta.env.VITE_HARNESS_ARN_RETAIL as string | undefined,
    Dashboard: placeholder(
      'Retail Inventory',
      'Demand forecasting, stock optimization and automated replenishment workflows.',
      ShoppingCart,
      'text-emerald-400',
      Boolean(import.meta.env.VITE_HARNESS_ARN_RETAIL),
    ),
  },
  {
    id: 'manufacturing-maintenance',
    name: 'Manufacturing Maintenance',
    icon: Factory,
    themeColor: 'text-amber-400',
    description:
      'Predictive maintenance, sensor anomaly detection and work-order automation.',
    enabled: Boolean(import.meta.env.VITE_HARNESS_ARN_MANUFACTURING),
    harnessArn: import.meta.env.VITE_HARNESS_ARN_MANUFACTURING as string | undefined,
    Dashboard: placeholder(
      'Manufacturing Maintenance',
      'Predictive maintenance, sensor anomaly detection and work-order automation.',
      Factory,
      'text-amber-400',
      Boolean(import.meta.env.VITE_HARNESS_ARN_MANUFACTURING),
    ),
  },
  {
    id: 'real-estate-valuation',
    name: 'Real Estate Valuation',
    icon: Building2,
    themeColor: 'text-cyan-400',
    description:
      'Comparable analysis, automated valuation models and market trend insights.',
    enabled: Boolean(import.meta.env.VITE_HARNESS_ARN_REALESTATE),
    harnessArn: import.meta.env.VITE_HARNESS_ARN_REALESTATE as string | undefined,
    Dashboard: placeholder(
      'Real Estate Valuation',
      'Comparable analysis, automated valuation models and market trend insights.',
      Building2,
      'text-cyan-400',
      Boolean(import.meta.env.VITE_HARNESS_ARN_REALESTATE),
    ),
  },
]

export function getIndustry(id: string | undefined): IndustryModule | undefined {
  return industries.find((industry) => industry.id === id)
}

export const DEFAULT_INDUSTRY_ID = 'finance'
