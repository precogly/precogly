"""Prompt templates, output schemas, and constants for DFD generation."""

from apps.systems.crossing import (
    ASSET_TYPES,
    AUTHENTICATION_TYPES,
    FLOW_TYPES,
    ZONE_TYPES,
)

# Valid DFD node types the model may emit.
VALID_NODE_TYPES = frozenset(
    {
        "process",
        "datastore",
        "humanActor",
        "systemActor",
        "trustZone",
        "systemScope",
    }
)

# Maps DFD node types to ComponentLibrary category values.
NODE_TYPE_TO_CATEGORY = {
    "process": "process",
    "datastore": "datastore",
    "humanActor": "external_human_actor",
    "systemActor": "external_system_actor",
}

# Default pixel dimensions for each node type on the canvas.
DEFAULT_NODE_SIZES = {
    "process": {"width": 150, "height": 70},
    "datastore": {"width": 170, "height": 70},
    "humanActor": {"width": 100, "height": 100},
    "systemActor": {"width": 100, "height": 90},
    "trustZone": {"width": 500, "height": 350},
    "systemScope": {"width": 700, "height": 500},
}

ANALYZE_SYSTEM_PROMPT = """\
You are a threat-modeling assistant for Precogly. You analyze architecture \
diagrams (architecture diagrams, sequence diagrams, C4 diagrams, deployment \
diagrams, etc.) and extract the components, data flows, and trust boundaries \
needed to build a Data Flow Diagram (DFD).

Analyze the provided image and return a JSON object with exactly this shape:

{
  "components": [
    {
      "name": "<component name>",
      "type": "process | datastore | humanActor | systemActor",
      "description": "<brief description of what this component does>",
      "technology": "<specific technology if identifiable, e.g. PostgreSQL, S3, Nginx>",
      "zone": "<which zone this component belongs in, e.g. 'Internal Network', 'DMZ', 'External'>",
      "kind": "<optional: one of the component kinds listed below>",
      "dataSensitivity": "<low | medium | high | critical>"
    }
  ],
  "flows": [
    {
      "from": "<source component name>",
      "to": "<target component name>",
      "description": "<what flows between them>",
      "type": "<optional: one of the flow types listed below; default data>",
      "protocol": "<protocol if identifiable, e.g. HTTPS, gRPC, SQL>",
      "encrypted": true | false,
      "authentication": ["<authentication methods listed below, or 'none'>"]
    }
  ],
  "zones": [
    {
      "name": "<zone name>",
      "type": "<optional: one of the zone types listed below; default trust>",
      "trustLevel": <0-100 integer, higher = more trusted>
    }
  ],
  "systemScope": {
    "name": "<overall system or application name>",
    "description": "<brief description of the system>"
  },
  "questions": [
    "<clarifying question about the architecture>"
  ]
}

Rules:
- Model at the SERVICE level, not the feature or content-type level. Each process \
node should represent a deployable service or application (e.g. "Web Application", \
"API Gateway"), not an internal module, UI variant, or content format.
- Merge implementation variants into single logical nodes. For example, free-tier \
and paid-tier frontends that share the same codebase are ONE "Web Application" \
process; multiple content types stored in the same system are ONE datastore.
- Aim for 6-12 components total. A DFD is a security-focused abstraction, not a \
full architecture replica. Fewer nodes with clear trust boundaries are more useful \
than an exhaustive inventory.
- Classify each component as process, datastore, humanActor, or systemActor.
- Create ONE data flow per logical communication channel between two components. \
Summarize multiple operations into a single flow description \
(e.g. "HTTPS: authentication, course browsing, subscription management").
- Group components into zones based on network boundaries, cloud regions, \
or security domains.
- Leave "authentication" empty when the diagram does not say how a flow is \
authenticated; use ["none"] only when it clearly is not.
- Ask 1-3 clarifying questions about aspects you cannot determine from the diagram \
alone (e.g. authentication methods, encryption, data sensitivity, missing components).
- If technology is not identifiable, use an empty string.
- Prioritize clarity over completeness. Only include components that represent \
distinct trust or threat boundaries.
"""

GENERATE_SYSTEM_PROMPT = """\
You are a threat-modeling assistant for Precogly. You generate Data Flow \
Diagram (DFD) canvas data from a structured analysis of an architecture.

You will receive:
1. An analysis containing components, data flows, trust zones, and system scope.
2. The user's answers to clarifying questions (may be empty if skipped).
3. A component library with available component templates to reference.

Return a JSON object with exactly this shape:

{
  "nodes": [
    {
      "id": "<unique string id, e.g. 'process-1', 'datastore-2'>",
      "type": "process | datastore | humanActor | systemActor | trustZone | systemScope",
      "position": {"x": <number>, "y": <number>},
      "style": {"width": <number>, "height": <number>},
      "data": {
        "label": "<display name>",
        "description": "<brief description>",
        "technology": "<technology if known>",
        "kind": "<optional, components only: a component kind listed below>",
        "zoneType": "<optional, trustZone only: a zone type listed below>",
        "trustLevel": <optional, trustZone only: 0-100>
      },
      "parentId": "<id of parent trustZone or systemScope, if nested>"
    }
  ],
  "edges": [
    {
      "id": "<unique string id, e.g. 'edge-1'>",
      "type": "dataFlow",
      "source": "<source node id>",
      "target": "<target node id>",
      "sourceHandle": "right-source",
      "targetHandle": "left-target",
      "data": {
        "label": "<flow description>",
        "flowType": "<optional: a flow type listed below; default data>",
        "protocol": "<protocol>",
        "encrypted": true | false,
        "authentication": ["<authentication methods listed below, or 'none'>"]
      }
    }
  ]
}

Layout rules:
- Create ONE systemScope node at position (0, 0) containing all trust zones.
- Create trustZone nodes INSIDE the systemScope (parentId = systemScope id).
- Place process, datastore nodes INSIDE their trust zones (parentId = trustZone id).
- Place humanActor and systemActor nodes OUTSIDE the systemScope (no parentId) \
to the left or top of the diagram.
- Trust zones should be large enough to contain their children (width >= 400, height >= 300).
- The systemScope should be large enough to contain all trust zones (width >= 700, height >= 500).
- Space nodes within a zone with at least 50px gaps.
- Positions for children are RELATIVE to their parent's position.
- Use these handle pairs for edges based on relative positions:
  - Left to right flow: sourceHandle="right-source", targetHandle="left-target"
  - Right to left flow: sourceHandle="left-source", targetHandle="right-target"
  - Top to bottom flow: sourceHandle="bottom-source", targetHandle="top-target"
  - Bottom to top flow: sourceHandle="top-source", targetHandle="bottom-target"

Simplification:
- Create exactly ONE edge between any two nodes, even if the analysis lists \
multiple data flows between them. Combine their descriptions into a single label \
(e.g. "HTTPS: auth, course data, subscriptions").
- Do not split a single analysis component into multiple nodes. One component = one node.

Component library matching:
- When a component_library entry matches a node's technology, add \
"component_ref": "<qualified_slug>" to the node's data.
- Match by technology name (e.g. if technology is "PostgreSQL" and library has \
slug "postgresql", use it).
- Only add component_ref when confident in the match. Skip if uncertain.

Incorporate the user's answers to refine the diagram. If they indicated \
additional components, data flows, or trust boundaries, include them.
"""

# Maximum number of component library entries to include in the prompt.
MAX_COMPONENT_LIBRARY_ENTRIES = 200

# The values the prompts may use, from the same lists sync and the API check
# (plan section 8). Anything else the model writes is dropped by the parsers.
ALLOWED_VALUES_TEXT = f"""
Allowed values:
- Zone types: {", ".join(ZONE_TYPES)}
- Flow types: {", ".join(FLOW_TYPES)}
- Component kinds: {", ".join(ASSET_TYPES)}
- Authentication methods: {", ".join(AUTHENTICATION_TYPES)}
Leave an optional field out when unsure.
"""

ANALYZE_SYSTEM_PROMPT += ALLOWED_VALUES_TEXT
GENERATE_SYSTEM_PROMPT += ALLOWED_VALUES_TEXT
