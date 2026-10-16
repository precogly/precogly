# DFD Editor

A self-contained Data Flow Diagram editor built with [@xyflow/react](https://reactflow.dev/).

## Structure

```
dfd-editor/
├── DFDEditor.tsx          # Main component
├── components/
│   ├── nodes/             # Custom node types (Process, DataStore, Actor, Boundaries)
│   ├── edges/             # DataFlowEdge with protocol/encryption metadata
│   └── panels/            # Right-side edit panels for nodes/edges
├── hooks/
│   ├── useDiagramState    # State, API integration, auto-save
│   ├── useUndoHistory     # Undo stack (Cmd+Z)
│   ├── useKeyboardShortcuts
│   └── useParentRelationships  # Boundary nesting logic
├── lib/
│   └── technology-registry    # 250+ technologies (AWS, Azure, GCP, etc.)
└── types/
    └── diagram.ts         # Node/edge type definitions
```

## Key Concepts

- **Nodes**: Process, DataStore, Actor, TrustZone (a "Zone" with a `zoneType` badge), SystemScope
- **Edges**: Flows (`flowType`; protocol, port and encryption on data-like types only; `authentication` as a list) and boundaries (`boundaryType`, `authenticationMethods`, `accessControlMethods`, crossing requirements under "Advanced")
- **Containers**: Nodes can be nested inside zones or system scopes (auto-detected on drag)
- **Canvas root**: `notationStyle` and `visibleFlowTypes` (the toolbar's flow type filter; missing means every type is drawn)
- **Defaults**: readers go through `lib/canvas-defaults.ts` (`getZoneType`, `getFlowType`, `getBoundaryType`, `getComponentKind`, `getAuthentication`); a canvas that sets no type keys needs no rewrite. A zone's trust level is shown only when set (`lib/zone-trust-level.ts`); a new zone starts at 50.

## Extending

**Add a node type:**
1. Create component in `components/nodes/`
2. Add type to `DiagramNodeType` in `types/diagram.ts`
3. Register in `nodeTypes` object in `DFDEditor.tsx`

**Add technologies:**
- Edit `lib/technology-registry.ts`
