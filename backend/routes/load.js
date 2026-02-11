const express = require('express');
const Load = require('../models/Load');
const { authenticate, authorize } = require('../middleware/combinedAuth');
const { postLoadSchema } = require('../validations/loadValidation');

const router = express.Router();

router.post('/post', authenticate, authorize('customer'), async (req, res) => {
  const { error, value } = postLoadSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      message: 'Validation failed',
      errors: error.details.map(detail => ({ field: detail.path.join('.'), message: detail.message }))
    });
  }

  const { material, requiredCapacity, from, to, consignorName, consigneeName } = value;

  const load = await Load.create({
    customer: req.user.userId,
    material,
    requiredCapacity,
    from,
    to,
    consignorName,
    consigneeName,
  });

  res.status(201).json(load);
});

router.get('/available', authenticate, authorize('admin'), async (req, res) => {
  const loads = await Load.find().sort({ createdAt: -1 });
  res.json(loads);
});

module.exports = router;
