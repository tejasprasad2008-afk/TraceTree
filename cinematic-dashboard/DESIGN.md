# TraceTree Unified Command Redesign

## Goal
Redesign the TraceTree Unified Command dashboard into a "Baroque-Renaissance meets old-money opera house" aesthetic using Next.js, Tailwind v4, and React 19.

## Architecture
- **Next.js 16 (App Router)**
- **Tailwind CSS v4**
- **Lucide React** for iconography (restrained)
- **Framer Motion** for delicate animations

## Component Strategy
- `NewspaperMasthead`: Editorial header with metadata.
- `HeroCollage`: Asymmetric grid with marble busts, video loops, and technical typography.
- `AISummaryBanner`: Narrative analysis with golden pulse animation.
- `IncidentFeed`: Styled as an open opera ledger.
- `TelemetryVisualizer`: Reskinned as an astronomical/architectural map.
- `HITLConsole`: Full-screen overlay modal with wax-seal/gold-embossed details.

## State Management
- `useTraceEvents`: WebSocket hook for real-time telemetry.
