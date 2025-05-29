import mongoose from "mongoose";



const userSchema = mongoose.Schema({

    personal_info: {
        fullname: {
            type: String,
            lowercase: true,
            required: true,
            minlength: [3, 'fullname must be 3 letters long'],
        },
        email: {
            type: String,
            required: true,
            lowercase: true,
            unique: true
        },
        password: String,
        user_id: {
            type: String,
            unique: true,
            sparse: true // щоб уникнути помилок, коли це поле відсутнє
        },
        bio: {
            type: String,
            maxlength: [200, 'Bio should not be more than 200'],
            default: "",
        },
        profile_img: {
            type: String,
            default: "",
        },
        role: {
            type: String,
            enam: ["user", "admin"],
            default: "user",

        }
    },
    account_info: {
        courses: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "courses"
        }]
    },
    google_auth: {
        type: Boolean,
        default: false
    },
    user_avatar_type: {
        type: String,
        enam: ["default", "google", "custom"],
        default: "default",
    },
    isBlocked: {
        type: Boolean,
        default: false
    }

},
    {
        timestamps: {
            createdAt: 'joinedAt'
        }

    })

export default mongoose.model("users", userSchema);