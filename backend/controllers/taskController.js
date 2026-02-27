const Task = require("../models/TaskModel");
const { z, ZodError } = require("zod");
const path = require("path");


const CreateTask = async (req, res) => {
    try{
        const taskSchema = z.object({
            title: z.string().min(3),
            description: z.string().optional(),
            due_date_time: z.coerce.date(),
            completion_date_time: z.coerce.date()
        });
        const validatedData = taskSchema.parse(req.body);
        
        const file_attachment_url = `/uploads/tasks/${req.file.filename}`;

        const taskCount = await Task.count({
            where: {
                user_id: req.user.id
            }
        });
        if(taskCount >= 50){
            return res.status(400).json({error: "Task limit reached (50 max)"});
        }
        
        const task = await Task.create({
            user_id: req.user.id,
            title: validatedData.title,
            description: validatedData.description,
            due_date_time: validatedData.due_date_time,
            completion_date_time: validatedData.completion_date_time,
            file_attachment: file_attachment_url
        });
        return res.status(201).json({message: "Task created successfully"});
    }
    catch(error){
        if(error instanceof ZodError){
            const formattedErrors = error.issues.map((issue) => ({
                field: issue.path[0],
                message: issue.message
            }));
            return res.status(400).json({error: formattedErrors});
        }
        return res.status(500).json({error: "An error occurred while creating task"});
    }
}

const AllTasks = async (req, res) => {
    try{
        const tasks = await Task.findAll({
            where: {
                user_id: req.user.id,
            }
        });
        return res.status(200).json({message: "All tasks loaded", tasks});
    }
    catch(error){
        return res.status(500).json({error: "An error occurred while loading tasks"});
    }
}

const EditTask = async (req, res) => {
    try{
        const taskSchema = z.object({
            title: z.string().min(3).optional(),
            description: z.string().optional(),
            due_date_time: z.coerce.date().optional(),
            completion_date_time: z.coerce.date().optional()
        });
        const validatedData = taskSchema.parse(req.body);
        const task = await Task.findOne({
            where: {
                id: req.params.id,
                user_id: req.user.id,
            }
        });
        
        if(!task){
            return res.status(404).json({error: "Task not found"}); 
        }
        await task.update(validatedData);
        return res.status(200).json({message: "Task updated successfully"});
    }
    catch(error){
        if(error instanceof ZodError){
            const formattedErrors = error.issues.map((issue) => ({
                field: issue.path[0],
                message: issue.message
            }));
            return res.status(400).json({error: formattedErrors});
        }
        return res.status(500).json({error: "An error occurred while updating task"});
    }
}

const DeleteTask = async (req, res) => {
    try{
        const task = await Task.destroy({
            where: {
                id: req.params.id,
                user_id: req.user.id
            }
        });
        return res.status(200).json({message: "Task deleted successfully"});
    }
    catch(error){
        return res.status(500).json({error: "An error occurred while deleting task"});
    }
}

const DownloadTaskFile = async (req, res) => {
    try{
        const task = await Task.findOne({
            where: {
                id: req.params.id,
                user_id: req.user.id
            }
        });
        if(!task){
            return res.status(404).json({error: "File not found"});
        }
        const filePath = path.join(__dirname, "..", task.file_attachment);
        
        return res.download(filePath);
        
    }
    catch(error){
        return res.status(500).json({error: "An error occurred while downloading"});
    }
}

module.exports = { CreateTask, AllTasks, EditTask, DeleteTask, DownloadTaskFile };

