const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 8004;
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN || 'http://localhost:3002';

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: DASHBOARD_ORIGIN,
    methods: ['GET', 'POST'],
  },
});

app.use(cors({ origin: DASHBOARD_ORIGIN }));
app.use(express.json());

io.on('connection', (socket) => {
  console.log('⚡️ War Room client connected');

  socket.on('disconnect', () => {
    console.log('❌ War Room client disconnected');
  });
});

app.post('/events/threat', (req, res) => {
  io.emit('threat_event', req.body);
  res.sendStatus(200);
});

app.post('/events/normal', (req, res) => {
  io.emit('normal_traffic', req.body);
  res.sendStatus(200);
});

app.post('/events/attack', (req, res) => {
  io.emit('attack_traffic', req.body);
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

app.post('/events/sentinel/profile', (req, res) => {
  io.emit('sentinel_profile', req.body);
  res.sendStatus(200);
});

app.post('/events/sentinel/simulation', (req, res) => {
  io.emit('sentinel_simulation', req.body);
  res.sendStatus(200);
});

app.post('/events/sentinel/rule', (req, res) => {
  io.emit('sentinel_rule', req.body);
  res.sendStatus(200);
});

app.post('/events/demo-step', (req, res) => {
  io.emit('demo_step', req.body.step);
  res.sendStatus(200);
});

server.listen(PORT, () => {
  console.log(`🚀 War Room server listening on port ${PORT}`);
  console.log(`🎯 Dashboard origin allowed: ${DASHBOARD_ORIGIN}`);
});
