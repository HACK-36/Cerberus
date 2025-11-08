# Cerberus War Room Dashboard - Implementation Spec

## Overview
The War Room transforms Cerberus terminal demos into a live, visual, event-driven dashboard that showcases the active defense system in real-time.

## Architecture

### Frontend (Next.js + React)
- **Real-time WebSocket connection** to backend event stream
- **Responsive grid layout** with live threat map, event cards, routing visualizer, labyrinth terminal, and AI analysis panels
- **Framer Motion animations** for smooth transitions and visual feedback
- **Custom canvas rendering** for threat map with attack/normal traffic visualization

### Backend (WebSocket Server)
- **Socket.IO server** on port 8004
- **Event emitters** integrated into Gatekeeper, Switch, Labyrinth, and Sentinel services
- **Demo orchestration** that streams events to dashboard in real-time

## Key Components Created

### 1. ThreatMap.tsx
- Canvas-based world map visualization
- Green lines for normal traffic (hundreds of requests)
- Red pulsing lines for attacks
- Real-time animation loop
- Legend showing traffic counts

### 2. EventCard.tsx
- Slides in from right when threat detected
- Color-coded by severity (low/medium/high/critical)
- Shows: event type, timestamp, source IP, session ID, score, action
- Pulsing animation for critical threats

### 3. RoutingVisualizer (TO CREATE)
```tsx
// Visual representation of traffic routing
- Two boxes: "PRODUCTION APP" (green) and "LABYRINTH" (dark red)
- Animated line showing session being rerouted from production → labyrinth
- Pulsing effect when labyrinth is active
```

### 4. LabyrinthTerminal (TO CREATE)
```tsx
// Terminal-style panel showing live attacker activity
- Scrolling log of attacker actions
- Syntax highlighting for endpoints
- Auto-scroll to latest activity
- Examples:
  > Probing /api/users endpoint...
  > Attempting to access admin panel...
  > Trying to access config...
  > Attempting file disclosure...
```

### 5. SentinelPanel (TO CREATE)
```tsx
// AI Analysis display
- Behavioral Profile section:
  - Intent: exploitation
  - Sophistication: 6.5/10 (automated tool)
  - TTPs: T1190, T1083, T1110
- Sandbox Simulation:
  - Status indicator (running/completed)
  - Verdict: EXPLOIT POSSIBLE/IMPROBABLE
  - Severity: 9.8/10
- Rule Generation:
  - Rule ID, Pattern, Action
  - Confidence meter
  - Policy decision (auto-apply/review/logged)
```

### 6. MetricsBar (TO CREATE)
```tsx
// Top-right metrics bar
- Total Requests
- Attacks Detected
- Attacks Blocked
- Sessions Rerouted
- Rules Generated
// All updating in real-time
```

## WebSocket Event Schema

### Events Emitted by Services

#### From Gatekeeper
```json
{
  "event": "threat_event",
  "data": {
    "id": "evt_xxx",
    "type": "sql_injection",
    "timestamp": "2025-11-08T...",
    "severity": "high",
    "source_ip": "203.0.113.42",
    "session_id": "demo_1762550698",
    "action": "tag_poi",
    "score": 62.21,
    "details": { "user_agent": "sqlmap/1.0", ... }
  }
}
```

#### From Switch
```json
{
  "event": "routing_update",
  "data": {
    "sessionId": "demo_1762550698",
    "isRerouting": true,
    "target": "labyrinth",
    "attackerIp": "203.0.113.42"
  }
}
```

#### From Labyrinth
```json
{
  "event": "labyrinth_activity",
  "data": {
    "sessionId": "demo_1762550698",
    "action": "GET",
    "endpoint": "/api/users?id=1' OR '1'='1"
  }
}
```

#### From Sentinel
```json
{
  "event": "sentinel_profile",
  "data": {
    "intent": "exploitation",
    "sophistication": 6.5,
    "ttps": ["T1190"]
  }
}

{
  "event": "sentinel_simulation",
  "data": {
    "status": "completed",
    "verdict": "exploit_possible",
    "severity": 9.8
  }
}

{
  "event": "sentinel_rule",
  "data": {
    "status": "generated",
    "ruleId": "vax_8f9ab2",
    "confidence": 0.92,
    "action": "block"
  }
}
```

#### Demo Step Sync
```json
{
  "event": "demo_step",
  "data": {
    "step": 2,
    "description": "Simulating SQL Injection attack"
  }
}
```

## Installation & Setup

```bash
cd dashboard
npm install
npm run dev
```

Dashboard will be available at `http://localhost:3002`

## Integration Points

### 1. Gatekeeper API Enhancement
Add WebSocket emission in `gatekeeper/api/main.py`:
```python
import socketio

sio = socketio.AsyncClient()

@app.post("/api/v1/inspect")
async def inspect_request(req: InspectRequest):
    # ... existing logic ...
    
    if action == "tag_poi" or action == "block":
        await sio.emit('threat_event', {
            'id': event_id,
            'type': 'sql_injection',  # detect from features
            'timestamp': datetime.utcnow().isoformat(),
            'severity': 'high' if scores.combined > 80 else 'medium',
            'source_ip': req.client_ip,
            'session_id': req.session_id,
            'action': action,
            'score': scores.combined,
            'details': {}
        })
```

### 2. Switch API Enhancement
Add routing emission in `switch/api/main.py`:
```python
@app.post("/api/v1/switch/pin")
async def pin_session(req: PinSessionRequest):
    # ... existing logic ...
    
    await sio.emit('routing_update', {
        'sessionId': req.session_id,
        'isRerouting': True,
        'target': 'labyrinth',
        'attackerIp': req.client_ip
    })
```

### 3. Labyrinth Capture Middleware
Add activity logging in `labyrinth/app/main.py`:
```python
@app.middleware("http")
async def log_to_war_room(request: Request, call_next):
    if is_pinned_session(request):
        await sio.emit('labyrinth_activity', {
            'sessionId': get_session_id(request),
            'action': request.method,
            'endpoint': str(request.url)
        })
    return await call_next(request)
```

### 4. Sentinel Analysis Streaming
Add analysis events in `sentinel/api/main.py`:
```python
# After profiling
await sio.emit('sentinel_profile', profile)

# During simulation
await sio.emit('sentinel_simulation', {
    'status': 'completed',
    'verdict': result['verdict'],
    'severity': result['severity']
})

# After rule generation
await sio.emit('sentinel_rule', {
    'status': 'generated',
    'ruleId': rule.rule_id,
    'confidence': rule.confidence,
    'action': rule.action
})
```

## WebSocket Server

Create `war-room-server/server.js`:
```javascript
const express = require('express');
const http = require('http');
const socketio = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: {
    origin: 'http://localhost:3002',
    methods: ['GET', 'POST']
  }
});

io.on('connection', (socket) => {
  console.log('War Room client connected');
  
  socket.on('disconnect', () => {
    console.log('War Room client disconnected');
  });
});

// HTTP endpoints for services to push events
app.post('/events/threat', (req, res) => {
  io.emit('threat_event', req.body);
  res.sendStatus(200);
});

app.post('/events/routing', (req, res) => {
  io.emit('routing_update', req.body);
  res.sendStatus(200);
});

app.post('/events/labyrinth', (req, res) => {
  io.emit('labyrinth_activity', req.body);
  res.sendStatus(200);
});

app.post('/events/sentinel', (req, res) => {
  const { type, data } = req.body;
  io.emit(type, data); // type: sentinel_profile, sentinel_simulation, sentinel_rule
  res.sendStatus(200);
});

server.listen(8004, () => {
  console.log('War Room server listening on port 8004');
});
```

## Demo Flow Visualization

### Step 1: Normal Traffic
- Map shows green lines flowing to server
- Metrics bar shows requests incrementing
- No event cards appear

### Step 2: Attack Detected
- **BAM!** Red pulsing line appears on map
- Event card slides in from right:
  ```
  THREAT DETECTED
  Event ID: evt_b1abdd17
  Type: SQL Injection
  Score: 62.21 (High)
  Action: TAG_POI
  ```
- Metrics: "Attacks Detected" +1

### Step 3: Routing Animation
- Routing Visualizer activates
- Green "Production App" box
- Dark red "Labyrinth" box starts pulsing
- Animated line shows session being disconnected from Production and rerouted to Labyrinth
- Metrics: "Sessions Rerouted" +1

### Step 4: Live Trap
- Labyrinth Terminal panel opens
- Terminal-style log scrolls:
  ```
  > Probing /api/users endpoint...
  > Attempting to access admin panel...
  > Trying to access config...
  > Attempting file disclosure...
  ```

### Step 5-7: Sentinel AI Panel
- AI Analysis panel slides out
- **Behavioral Profile** fills in:
  ```
  Intent: exploitation
  Sophistication: 6.5/10 (automated tool)
  TTPs: T1190 (Exploit Public-Facing Application)
  ```
- **Sandbox Status**: "Running simulation..." → "Simulation complete."
- **Verdict**: "EXPLOIT POSSIBLE (Severity: 9.8/10)"
- **Rule Generation**: Shows rule ID, pattern, confidence meter filling to 92%

### Step 8: Policy Decision
- **IF High Confidence (>90%):**
  - Huge red banner appears: **"HIGH SEVERITY THREAT! PUSHING VACCINE TO GLOBAL BLOCKLIST!"**
  - Rule shown with "AUTO-APPLIED" badge
  - Metrics: "Rules Generated" +1
  
- **IF Low Confidence (<70%):**
  - Yellow banner: **"AI ORCHESTRATOR: MONITORING. Attack may be false positive. Logging for analysis."**
  - Explains intelligent decision to avoid false positive

### Step 9: Verification
- Same attack from new IP appears on map (red line)
- **IF Rule Applied:**
  - Red line flashes and disappears immediately
  - Event card: "ATTACK BLOCKED (VACCINE vax_8f9ab2...)"
  - Metrics: "Attacks Blocked" +1
  
- **IF Not Applied:**
  - Shows tagging/monitoring action
  - Demonstrates adaptive response

## Advanced Features

### Active Labyrinth (Adaptive Deception)

#### Low-Skill Attacker
```
Sentinel detects: Sophistication 2/10
→ Feedback to Labyrinth: "Keep them busy"
→ Labyrinth adapts: Intentionally leaks fake config.bak
→ Terminal shows: "> Found config.bak... downloading fake credentials"
→ Attacker wastes 20 minutes on fake data
```

#### High-Skill Attacker (APT)
```
Sentinel detects: Sophistication 9/10, Intent: Data Exfiltration
→ Feedback to Labyrinth: "Escalate. Need their tools."
→ Labyrinth adapts: Presents fake S3 bucket endpoint
→ Terminal shows: "> Found S3 bucket... attempting exfiltration"
→ Attacker uses custom zero-day tool
→ WIN: Captured custom malware in sandbox
```

## Deployment

### Development
```bash
# Terminal 1: Start services
docker compose up -d

# Terminal 2: Start War Room server
cd war-room-server
node server.js

# Terminal 3: Start dashboard
cd dashboard
npm run dev

# Terminal 4: Run demo
./scripts/demo.sh
```

### Production
```bash
docker compose -f docker-compose.prod.yml up -d
# Includes war-room-server and dashboard in stack
```

## Success Metrics

The War Room successfully demonstrates Cerberus if:
1. ✅ Live map shows normal vs attack traffic visually
2. ✅ Event cards appear instantly when threats detected
3. ✅ Routing animation clearly shows attacker being deceived
4. ✅ Labyrinth terminal streams live attacker behavior
5. ✅ Sentinel AI panel shows intelligent analysis
6. ✅ Rule generation and application is visualized
7. ✅ Subsequent attacks are blocked (or logged intelligently)
8. ✅ Judge can understand the entire flow without terminal

## Next Steps

1. Create remaining components (RoutingVisualizer, LabyrinthTerminal, SentinelPanel, MetricsBar)
2. Implement WebSocket server (war-room-server/server.js)
3. Add event emission to all Cerberus services
4. Test with live demo.sh script
5. Add adaptive Labyrinth logic based on Sentinel profiling
6. Deploy to production stack
