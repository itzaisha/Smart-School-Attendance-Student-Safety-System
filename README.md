# Smart School Attendance & Student Safety System

A complete, beginner-friendly university AICT project featuring **QR Code Attendance** and **Guardian-Verified Student Pickup Safety**.

This repository contains:
1. **Live Interactive Web Application** (React + TypeScript + Express + SQLite) running on port `3000`.
2. **Complete PHP + MySQL + XAMPP Source Folder** (`php-xampp-project/`) ready to run locally on Windows 11 XAMPP, plus `database/smart_school_db.sql`.

---

## Sample Login Credentials

| Role  | Username | Password   | Full Name           |
|-------|----------|------------|---------------------|
| Admin | `admin`  | `admin123` | Dr. Ayesha Siddiqui |
| Guard | `guard`  | `guard123` | Muhammad Tariq      |
| Guard | `guard2` | `guard123` | Kamran Raza         |

---

## XAMPP Installation Instructions (Windows 11)

1. **Install XAMPP** on Windows 11 (`C:\xampp`).
2. **Copy Project Folder**:
   - Copy the `php-xampp-project` folder into `C:\xampp\htdocs\` and rename it to `smart_school_system` (`C:\xampp\htdocs\smart_school_system`).
   - *(Or click "Download PHP + MySQL XAMPP Package (.zip)" on the login footer in the live web app and extract to `C:\xampp\htdocs\smart_school_system`.)*
3. **Start Apache & MySQL**:
   - Open **XAMPP Control Panel**.
   - Click **Start** next to **Apache** and **MySQL**.
4. **Import the MySQL Database**:
   - Open your browser and go to `http://localhost/phpmyadmin`.
   - Click **New** in the left sidebar, enter database name `smart_school_db`, and click **Create**.
   - Select `smart_school_db`, open the **Import** tab, click **Choose File**, select `C:\xampp\htdocs\smart_school_system\database\smart_school_db.sql`, and click **Import** (or **Go**).
5. **Open the Website**:
   - Visit `http://localhost/smart_school_system/` in Chrome or Edge.
   - Sign in using the sample **Admin** or **Guard** credentials above.

---

## Database Tables (`smart_school_db`)

1. `users` — Admin and Guard accounts (`id`, `username`, `password`, `full_name`, `role`)
2. `students` — Student profiles & QR code payloads (`id`, `student_id`, `student_name`, `class_name`, `section`, `roll_number`, `parent_name`, `parent_contact`, `qr_code_data`)
3. `guardians` — Linked guardians with `authorization_status` (`Authorized` / `Unauthorized`) and foreign key to `students`
4. `attendance` — Daily check-in records with `UNIQUE(student_id, attendance_date)` to prevent duplicate attendance on the same day
5. `pickup` — Guardian-verified pickup logs (`Verified` / `Rejected`) with foreign keys to `students`, `guardians`, and `users`
