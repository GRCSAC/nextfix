'use strict';
const express = require('express');
const users = require('../services/users');

const router = express.Router();

// Authenticated (mounted behind requireAuth in app.js).
router.post('/users/normalize', (req, res) => {
  const name = users.normalizeName(req.body.name);
  res.json({ name });
});

module.exports = router;
