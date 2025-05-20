import mongoose from "mongoose";

const notificationSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "users",
        required: true
    },
    type: {
        type: String,
        enum: ["TaskAssigned", "TaskReviewed", "NewLessonPublished"],
        required: true
    },
    message: {
        type: String,
        required: true
    },
    link: String,
    status: {
        type: String,
        enum: ["SENT", "DELIVERED", "READ"],
        default: "SENT"
    },
    sentAt: Date
}, {
    timestamps: { createdAt: 'createdAt' }
});

export default mongoose.model("notifications", notificationSchema);
