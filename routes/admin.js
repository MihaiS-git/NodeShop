const path = require('path');
const { check, body } = require('express-validator');
const express = require('express');

const adminController = require('../controllers/admin');
const isAuth = require('../middleware/is-auth');

const router = express.Router();

router.get('/add-product', isAuth, adminController.getAddProduct);

router.get('/products', isAuth, adminController.getProducts);

router.post('/add-product',
    [
        body('title')
            .isAlphanumeric()
            .isLength({ min: 3 })
            .trim(),
        body('price')
            .isFloat(),
        body('description')
            .isLength({ min: 5, max: 200 })
            .trim()
    ],
    isAuth,
    adminController.postAddProduct
);

router.get('/edit-product/:productId', isAuth, adminController.getEditProduct);

router.post('/edit-product',
    [
        body('title')
            .isString()
            .isLength({ min: 3 })
            .trim()
            .withMessage('Title must be at least 3 characters long.'),
        body('price')
            .isFloat()
            .withMessage('Please enter a valid price.'),
        body('description')
            .isLength({ min: 5, max: 200 })
            .trim()
            .withMessage('Description must be between 5 and 200 characters.')
    ],
    isAuth,
    adminController.postEditProduct
);

router.delete('/product/:productId', isAuth, adminController.deleteProduct);

module.exports = router;
