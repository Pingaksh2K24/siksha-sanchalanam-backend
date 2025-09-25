import express from 'express';
import { registerUser, loginUser, getAllUserList, getUserDetails, uploadFile, upload, getAllDropdowns, deleteUser } from '../controllers/authController.js';

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/getAllUserList', getAllUserList);
router.get('/users/:id', getUserDetails);
router.post('/upload', upload.single('file'), uploadFile);
router.get('/getAllDropdowns', getAllDropdowns);
router.delete('/users/:id', deleteUser);

export default router;