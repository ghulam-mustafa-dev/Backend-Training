const express = require("express");
const { CreateTask, AllTasks, EditTask, DeleteTask, DownloadTaskFile, SimilarTasks } = require("../controllers/taskController");
const router = express.Router();
const upload = require("../middleware/multerMiddleware");
const authMiddleware = require("../middleware/authMiddleware");

router.post("/", upload.single("file_attachment"), authMiddleware, CreateTask);
router.get("/", authMiddleware, AllTasks);
router.put("/:id", upload.single("file_attachment"), authMiddleware, EditTask);
router.delete("/:id", authMiddleware, DeleteTask);
router.get("/:id/download", authMiddleware, DownloadTaskFile);
router.get("/:id/similar", authMiddleware, SimilarTasks);

module.exports = router;