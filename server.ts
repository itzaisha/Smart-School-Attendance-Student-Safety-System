import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { ZipArchive } from 'archiver';
import { createServer as createViteServer } from 'vite';
import db, {
  initializeDatabase,
  getTodayDate,
  getCurrentTimeFormatted,
} from './server/db.ts';

initializeDatabase();

interface SessionEntry {
  id: number;
  username: string;
  fullName: string;
  role: 'admin' | 'guard';
}

// In-memory session store (cleared on restart; clients re-authenticate cleanly)
const sessions = new Map<string, SessionEntry>();

interface AuthenticatedRequest extends Request {
  user?: SessionEntry;
}

function getTokenFromRequest(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const match = cookieHeader
      .split(';')
      .map((c) => c.trim())
      .find((c) => c.startsWith('ss_session='));
    if (match) {
      return decodeURIComponent(match.split('=')[1] || '');
    }
  }
  return null;
}

function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const token = getTokenFromRequest(req);
  if (!token || !sessions.has(token)) {
    res.status(401).json({ error: 'Authentication required. Please log in.' });
    return;
  }
  req.user = sessions.get(token);
  next();
}

function requireRole(...roles: Array<'admin' | 'guard'>) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: 'Access denied for your role.' });
      return;
    }
    next();
  };
}

function createParentNotification(params: {
  studentId: string;
  parentName: string;
  parentContact: string;
  eventType: 'Arrival' | 'Pickup' | 'Security Alert' | 'Absence' | 'General';
  channel?: 'SMS' | 'WhatsApp' | 'App Alert';
  message: string;
  sentDate?: string;
  sentTime?: string;
}) {
  const sentDate = params.sentDate || getTodayDate();
  const sentTime = params.sentTime || getCurrentTimeFormatted();
  const channel = params.channel || 'SMS';

  const info = db
    .prepare(`
      INSERT INTO notifications (student_id, parent_name, parent_contact, event_type, channel, message, delivery_status, sent_date, sent_time)
      VALUES (?, ?, ?, ?, ?, ?, 'Sent', ?, ?)
    `)
    .run(
      params.studentId,
      params.parentName,
      params.parentContact,
      params.eventType,
      channel,
      params.message,
      sentDate,
      sentTime
    );

  return db
    .prepare(`
      SELECT n.*, s.student_name, s.class_name
      FROM notifications n
      JOIN students s ON n.student_id = s.student_id
      WHERE n.id = ?
    `)
    .get(info.lastInsertRowid);
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // =========================================================
  // 1. AUTHENTICATION ROUTES
  // =========================================================
  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { username, password, role } = req.body as {
      username?: string;
      password?: string;
      role?: 'admin' | 'guard';
    };

    if (!username || !password) {
      res.status(400).json({ error: 'Please enter both username and password.' });
      return;
    }

    const user = db
      .prepare('SELECT id, username, password, full_name, role FROM users WHERE username = ?')
      .get(username.trim()) as
      | { id: number; username: string; password: string; full_name: string; role: 'admin' | 'guard' }
      | undefined;

    if (!user || user.password !== password) {
      res.status(401).json({ error: 'Invalid username or password.' });
      return;
    }

    if (role && user.role !== role) {
      res.status(403).json({
        error: `This account belongs to the "${user.role}" role. Please use the ${user.role.toUpperCase()} login tab.`,
      });
      return;
    }

    const token = crypto.randomBytes(24).toString('hex');
    const sessionUser: SessionEntry = {
      id: user.id,
      username: user.username,
      fullName: user.full_name,
      role: user.role,
    };
    sessions.set(token, sessionUser);

    res.setHeader(
      'Set-Cookie',
      `ss_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax`
    );
    res.json({ token, user: sessionUser });
  });

  app.post('/api/auth/logout', (req: Request, res: Response) => {
    const token = getTokenFromRequest(req);
    if (token) {
      sessions.delete(token);
    }
    res.setHeader('Set-Cookie', 'ss_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax');
    res.json({ success: true });
  });

  app.get('/api/auth/me', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    res.json({ user: req.user });
  });

  // =========================================================
  // 2. DASHBOARD ROUTE
  // =========================================================
  app.get('/api/dashboard', requireAuth, (_req: AuthenticatedRequest, res: Response) => {
    const today = getTodayDate();

    const totalRow = db.prepare('SELECT COUNT(*) as count FROM students').get() as { count: number };
    const presentRow = db
      .prepare("SELECT COUNT(DISTINCT student_id) as count FROM attendance WHERE attendance_date = ? AND status = 'Present'")
      .get(today) as { count: number };
    const pickedUpRow = db
      .prepare("SELECT COUNT(DISTINCT student_id) as count FROM pickup WHERE pickup_date = ? AND verification_status = 'Verified'")
      .get(today) as { count: number };
    const notificationsRow = db
      .prepare('SELECT COUNT(*) as count FROM notifications WHERE sent_date = ?')
      .get(today) as { count: number };

    const totalStudents = totalRow.count;
    const presentToday = presentRow.count;
    const absentToday = Math.max(0, totalStudents - presentToday);
    const pickedUpToday = pickedUpRow.count;
    const notificationsToday = notificationsRow.count;

    const recentAttendance = db
      .prepare(`
        SELECT a.id, a.student_id, s.student_name, s.class_name, s.roll_number,
               a.attendance_date, a.arrival_time, a.status, u.full_name as marked_by_name, a.created_at
        FROM attendance a
        JOIN students s ON a.student_id = s.student_id
        LEFT JOIN users u ON a.marked_by = u.id
        ORDER BY a.attendance_date DESC, a.id DESC
        LIMIT 6
      `)
      .all();

    const recentStudents = db
      .prepare(`
        SELECT * FROM students
        ORDER BY id DESC
        LIMIT 6
      `)
      .all();

    const recentPickups = db
      .prepare(`
        SELECT p.*, s.student_name, s.class_name, g.guardian_name, g.relationship
        FROM pickup p
        JOIN students s ON p.student_id = s.student_id
        JOIN guardians g ON p.guardian_id = g.id
        ORDER BY p.pickup_date DESC, p.id DESC
        LIMIT 6
      `)
      .all();

    const recentNotifications = db
      .prepare(`
        SELECT n.*, s.student_name, s.class_name
        FROM notifications n
        JOIN students s ON n.student_id = s.student_id
        ORDER BY n.sent_date DESC, n.id DESC
        LIMIT 6
      `)
      .all();

    res.json({
      today,
      stats: {
        totalStudents,
        presentToday,
        absentToday,
        pickedUpToday,
        notificationsToday,
      },
      recentAttendance,
      recentStudents,
      recentPickups,
      recentNotifications,
    });
  });

  // =========================================================
  // 3. STUDENT MANAGEMENT ROUTES
  // =========================================================
  app.get('/api/students', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const q = String(req.query.q || '').trim();
    if (q) {
      const pattern = `%${q}%`;
      const rows = db
        .prepare(`
          SELECT * FROM students
          WHERE student_id LIKE ?
             OR student_name LIKE ?
             OR class_name LIKE ?
             OR roll_number LIKE ?
             OR parent_name LIKE ?
          ORDER BY id DESC
        `)
        .all(pattern, pattern, pattern, pattern, pattern);
      res.json({ students: rows });
      return;
    }

    const rows = db.prepare('SELECT * FROM students ORDER BY id DESC').all();
    res.json({ students: rows });
  });

  app.get('/api/students/:studentId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const studentId = String(req.params.studentId).trim();
    const student = db
      .prepare('SELECT * FROM students WHERE student_id = ?')
      .get(studentId);
    if (!student) {
      res.status(404).json({ error: 'Student not found.' });
      return;
    }

    const guardians = db
      .prepare('SELECT * FROM guardians WHERE student_id = ? ORDER BY authorization_status ASC, id ASC')
      .all(studentId);

    const today = getTodayDate();
    const todayAttendance = db
      .prepare('SELECT * FROM attendance WHERE student_id = ? AND attendance_date = ?')
      .get(studentId, today);
    const todayPickup = db
      .prepare(`
        SELECT p.*, g.guardian_name, g.relationship
        FROM pickup p
        JOIN guardians g ON p.guardian_id = g.id
        WHERE p.student_id = ? AND p.pickup_date = ? AND p.verification_status = 'Verified'
        ORDER BY p.id DESC LIMIT 1
      `)
      .get(studentId, today);

    res.json({ student, guardians, todayAttendance, todayPickup });
  });

  app.post('/api/students', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res: Response) => {
    const {
      student_id,
      student_name,
      class_name,
      roll_number,
      parent_name,
      parent_contact,
    } = req.body as Record<string, string>;

    if (
      !student_id?.trim() ||
      !student_name?.trim() ||
      !class_name?.trim() ||
      !roll_number?.trim() ||
      !parent_name?.trim() ||
      !parent_contact?.trim()
    ) {
      res.status(400).json({ error: 'All student registration fields are required.' });
      return;
    }

    const cleanId = student_id.trim().toUpperCase();
    const existing = db.prepare('SELECT id FROM students WHERE student_id = ?').get(cleanId);
    if (existing) {
      res.status(409).json({ error: `Student ID "${cleanId}" is already registered.` });
      return;
    }

    const qrCodeData = `SMART_SCHOOL:${cleanId}`;

    const info = db
      .prepare(`
        INSERT INTO students (student_id, student_name, class_name, roll_number, parent_name, parent_contact, qr_code_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        cleanId,
        student_name.trim(),
        class_name.trim(),
        roll_number.trim(),
        parent_name.trim(),
        parent_contact.trim(),
        qrCodeData
      );

    db.prepare(`
      INSERT INTO guardians (student_id, guardian_name, relationship, contact_number, authorization_status)
      VALUES (?, ?, 'Parent', ?, 'Authorized')
    `).run(cleanId, parent_name.trim(), parent_contact.trim());

    const created = db.prepare('SELECT * FROM students WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({
      message: `Student ${student_name.trim()} (${cleanId}) registered and QR code generated.`,
      student: created,
    });
  });

  app.put('/api/students/:studentId', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res: Response) => {
    const targetId = String(req.params.studentId).trim();
    const {
      student_name,
      class_name,
      roll_number,
      parent_name,
      parent_contact,
    } = req.body as Record<string, string>;

    const existing = db.prepare('SELECT * FROM students WHERE student_id = ?').get(targetId);
    if (!existing) {
      res.status(404).json({ error: 'Student not found.' });
      return;
    }

    if (
      !student_name?.trim() ||
      !class_name?.trim() ||
      !roll_number?.trim() ||
      !parent_name?.trim() ||
      !parent_contact?.trim()
    ) {
      res.status(400).json({ error: 'All student fields are required.' });
      return;
    }

    db.prepare(`
      UPDATE students
      SET student_name = ?, class_name = ?, roll_number = ?, parent_name = ?, parent_contact = ?
      WHERE student_id = ?
    `).run(
      student_name.trim(),
      class_name.trim(),
      roll_number.trim(),
      parent_name.trim(),
      parent_contact.trim(),
      targetId
    );

    const updated = db.prepare('SELECT * FROM students WHERE student_id = ?').get(targetId);
    res.json({ message: 'Student details updated successfully.', student: updated });
  });

  app.delete('/api/students/:studentId', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res: Response) => {
    const targetId = String(req.params.studentId).trim();
    const existing = db.prepare('SELECT student_name FROM students WHERE student_id = ?').get(targetId) as
      | { student_name: string }
      | undefined;

    if (!existing) {
      res.status(404).json({ error: 'Student not found.' });
      return;
    }

    db.prepare('DELETE FROM students WHERE student_id = ?').run(targetId);
    res.json({ message: `Student ${existing.student_name} (${targetId}) deleted.` });
  });

  // =========================================================
  // 4. GUARDIAN MANAGEMENT ROUTES
  // =========================================================
  app.get('/api/guardians', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const q = String(req.query.q || '').trim();
    const studentId = String(req.query.studentId || '').trim();

    let sql = `
      SELECT g.*, s.student_name, s.class_name
      FROM guardians g
      JOIN students s ON g.student_id = s.student_id
    `;
    const params: string[] = [];
    const clauses: string[] = [];

    if (studentId) {
      clauses.push('g.student_id = ?');
      params.push(studentId);
    }
    if (q) {
      clauses.push('(g.guardian_name LIKE ? OR g.student_id LIKE ? OR s.student_name LIKE ? OR g.relationship LIKE ?)');
      const pat = `%${q}%`;
      params.push(pat, pat, pat, pat);
    }

    if (clauses.length > 0) {
      sql += ' WHERE ' + clauses.join(' AND ');
    }
    sql += ' ORDER BY g.id DESC';

    const guardians = db.prepare(sql).all(...params);
    res.json({ guardians });
  });

  app.post('/api/guardians', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res: Response) => {
    const {
      student_id,
      guardian_name,
      relationship,
      contact_number,
      authorization_status,
    } = req.body as Record<string, string>;

    if (
      !student_id?.trim() ||
      !guardian_name?.trim() ||
      !relationship?.trim() ||
      !contact_number?.trim() ||
      !['Authorized', 'Unauthorized'].includes(authorization_status)
    ) {
      res.status(400).json({ error: 'All guardian fields and a valid authorization status are required.' });
      return;
    }

    const cleanStudentId = student_id.trim().toUpperCase();
    const student = db.prepare('SELECT student_id FROM students WHERE student_id = ?').get(cleanStudentId);
    if (!student) {
      res.status(404).json({ error: `Student ID "${cleanStudentId}" does not exist.` });
      return;
    }

    const info = db
      .prepare(`
        INSERT INTO guardians (student_id, guardian_name, relationship, contact_number, authorization_status)
        VALUES (?, ?, ?, ?, ?)
      `)
      .run(
        cleanStudentId,
        guardian_name.trim(),
        relationship.trim(),
        contact_number.trim(),
        authorization_status
      );

    const created = db
      .prepare(`
        SELECT g.*, s.student_name, s.class_name
        FROM guardians g
        JOIN students s ON g.student_id = s.student_id
        WHERE g.id = ?
      `)
      .get(info.lastInsertRowid);

    res.status(201).json({
      message: `Guardian ${guardian_name.trim()} added (${authorization_status}).`,
      guardian: created,
    });
  });

  app.put('/api/guardians/:id', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    const {
      student_id,
      guardian_name,
      relationship,
      contact_number,
      authorization_status,
    } = req.body as Record<string, string>;

    const existing = db.prepare('SELECT * FROM guardians WHERE id = ?').get(id);
    if (!existing) {
      res.status(404).json({ error: 'Guardian record not found.' });
      return;
    }

    if (
      !student_id?.trim() ||
      !guardian_name?.trim() ||
      !relationship?.trim() ||
      !contact_number?.trim() ||
      !['Authorized', 'Unauthorized'].includes(authorization_status)
    ) {
      res.status(400).json({ error: 'All guardian fields and valid authorization status are required.' });
      return;
    }

    const cleanStudentId = student_id.trim().toUpperCase();
    const student = db.prepare('SELECT student_id FROM students WHERE student_id = ?').get(cleanStudentId);
    if (!student) {
      res.status(404).json({ error: `Student ID "${cleanStudentId}" does not exist.` });
      return;
    }

    db.prepare(`
      UPDATE guardians
      SET student_id = ?, guardian_name = ?, relationship = ?, contact_number = ?, authorization_status = ?
      WHERE id = ?
    `).run(
      cleanStudentId,
      guardian_name.trim(),
      relationship.trim(),
      contact_number.trim(),
      authorization_status,
      id
    );

    const updated = db
      .prepare(`
        SELECT g.*, s.student_name, s.class_name
        FROM guardians g
        JOIN students s ON g.student_id = s.student_id
        WHERE g.id = ?
      `)
      .get(id);

    res.json({ message: 'Guardian updated successfully.', guardian: updated });
  });

  app.delete('/api/guardians/:id', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT id FROM guardians WHERE id = ?').get(id);
    if (!existing) {
      res.status(404).json({ error: 'Guardian record not found.' });
      return;
    }
    db.prepare('DELETE FROM guardians WHERE id = ?').run(id);
    res.json({ message: 'Guardian deleted successfully.' });
  });

  // =========================================================
  // 5. QR ATTENDANCE & ATTENDANCE RECORDS ROUTES
  // =========================================================
  app.get('/api/attendance', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const q = String(req.query.q || '').trim();
    const date = String(req.query.date || '').trim();

    let sql = `
      SELECT a.id, a.student_id, s.student_name, s.class_name, s.roll_number,
             a.attendance_date, a.arrival_time, a.status, u.full_name as marked_by_name, a.created_at
      FROM attendance a
      JOIN students s ON a.student_id = s.student_id
      LEFT JOIN users u ON a.marked_by = u.id
    `;
    const params: string[] = [];
    const clauses: string[] = [];

    if (date) {
      clauses.push('a.attendance_date = ?');
      params.push(date);
    }
    if (q) {
      clauses.push('(s.student_name LIKE ? OR a.student_id LIKE ? OR s.class_name LIKE ?)');
      const pat = `%${q}%`;
      params.push(pat, pat, pat);
    }

    if (clauses.length > 0) {
      sql += ' WHERE ' + clauses.join(' AND ');
    }
    sql += ' ORDER BY a.attendance_date DESC, a.id DESC';

    const records = db.prepare(sql).all(...params);
    res.json({ records });
  });

  // Resolve QR code / student ID preview before confirming or directly marking
  app.post('/api/attendance/lookup', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const { qrCode, studentId } = req.body as { qrCode?: string; studentId?: string };
    const raw = (qrCode || studentId || '').trim();

    if (!raw) {
      res.status(400).json({ error: 'No QR code or Student ID provided.' });
      return;
    }

    let student = db
      .prepare('SELECT * FROM students WHERE qr_code_data = ? OR student_id = ?')
      .get(raw, raw.toUpperCase()) as Record<string, unknown> | undefined;

    if (!student && raw.startsWith('SMART_SCHOOL:')) {
      const extracted = raw.replace('SMART_SCHOOL:', '').trim().toUpperCase();
      student = db.prepare('SELECT * FROM students WHERE student_id = ?').get(extracted) as
        | Record<string, unknown>
        | undefined;
    }

    if (!student) {
      res.status(404).json({
        error: `Invalid QR code ("${raw}"). No registered student matches this code.`,
      });
      return;
    }

    const today = getTodayDate();
    const existingAttendance = db
      .prepare('SELECT * FROM attendance WHERE student_id = ? AND attendance_date = ?')
      .get(student.student_id as string, today);

    res.json({
      student,
      today,
      alreadyMarked: Boolean(existingAttendance),
      existingAttendance: existingAttendance || null,
    });
  });

  app.post('/api/attendance/mark', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const { qrCode, studentId } = req.body as { qrCode?: string; studentId?: string };
    const raw = (qrCode || studentId || '').trim();

    if (!raw) {
      res.status(400).json({ error: 'Please scan a QR code or select a student.' });
      return;
    }

    const student = db
      .prepare('SELECT * FROM students WHERE qr_code_data = ? OR student_id = ?')
      .get(raw, raw.toUpperCase()) as
      | {
          student_id: string;
          student_name: string;
          class_name: string;
          roll_number: string;
          parent_name: string;
          parent_contact: string;
        }
      | undefined;

    if (!student) {
      res.status(404).json({
        error: `Invalid QR code ("${raw}"). Student record does not exist.`,
      });
      return;
    }

    const today = getTodayDate();
    const existing = db
      .prepare('SELECT * FROM attendance WHERE student_id = ? AND attendance_date = ?')
      .get(student.student_id, today) as { arrival_time: string } | undefined;

    if (existing) {
      res.status(409).json({
        error: `Duplicate attendance prevented: ${student.student_name} (${student.student_id}) was already marked Present today at ${existing.arrival_time}.`,
        student,
        existing,
      });
      return;
    }

    const arrivalTime = getCurrentTimeFormatted();
    const info = db
      .prepare(`
        INSERT INTO attendance (student_id, attendance_date, arrival_time, status, marked_by)
        VALUES (?, ?, ?, 'Present', ?)
      `)
      .run(student.student_id, today, arrivalTime, req.user!.id);

    const record = db
      .prepare(`
        SELECT a.id, a.student_id, s.student_name, s.class_name, s.roll_number,
               a.attendance_date, a.arrival_time, a.status, u.full_name as marked_by_name, a.created_at
        FROM attendance a
        JOIN students s ON a.student_id = s.student_id
        LEFT JOIN users u ON a.marked_by = u.id
        WHERE a.id = ?
      `)
      .get(info.lastInsertRowid);

    const notification = createParentNotification({
      studentId: student.student_id,
      parentName: student.parent_name,
      parentContact: student.parent_contact,
      eventType: 'Arrival',
      channel: 'SMS',
      message: `Assalam-o-Alaikum ${student.parent_name}, ${student.student_name} (${student.student_id}, ${student.class_name}) arrived safely at school on ${today} at ${arrivalTime}.`,
      sentDate: today,
      sentTime: arrivalTime,
    });

    res.status(201).json({
      message: `Attendance marked Present for ${student.student_name} (${student.student_id}) at ${arrivalTime}. Parent notification sent to ${student.parent_name} (${student.parent_contact}).`,
      record,
      student,
      notification,
    });
  });

  // =========================================================
  // 6. STUDENT PICKUP & VERIFICATION ROUTES
  // =========================================================
  app.get('/api/pickups', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const q = String(req.query.q || '').trim();
    const date = String(req.query.date || '').trim();

    let sql = `
      SELECT p.*, s.student_name, s.class_name, g.guardian_name, g.relationship, g.authorization_status
      FROM pickup p
      JOIN students s ON p.student_id = s.student_id
      JOIN guardians g ON p.guardian_id = g.id
    `;
    const params: string[] = [];
    const clauses: string[] = [];

    if (date) {
      clauses.push('p.pickup_date = ?');
      params.push(date);
    }
    if (q) {
      clauses.push('(s.student_name LIKE ? OR p.student_id LIKE ? OR g.guardian_name LIKE ? OR p.guard_name LIKE ?)');
      const pat = `%${q}%`;
      params.push(pat, pat, pat, pat);
    }

    if (clauses.length > 0) {
      sql += ' WHERE ' + clauses.join(' AND ');
    }
    sql += ' ORDER BY p.pickup_date DESC, p.id DESC';

    const pickups = db.prepare(sql).all(...params);
    res.json({ pickups });
  });

  app.post('/api/pickups', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const { studentId, guardianId, notes, recordRejectedAttempt } = req.body as {
      studentId?: string;
      guardianId?: number;
      notes?: string;
      recordRejectedAttempt?: boolean;
    };

    if (!studentId || !guardianId) {
      res.status(400).json({ error: 'Student and Guardian selection are required for pickup verification.' });
      return;
    }

    const student = db
      .prepare('SELECT * FROM students WHERE student_id = ?')
      .get(studentId.trim().toUpperCase()) as
      | {
          student_id: string;
          student_name: string;
          class_name: string;
          parent_name: string;
          parent_contact: string;
        }
      | undefined;

    if (!student) {
      res.status(404).json({ error: 'Student not found.' });
      return;
    }

    const guardian = db
      .prepare('SELECT * FROM guardians WHERE id = ? AND student_id = ?')
      .get(Number(guardianId), student.student_id) as
      | { id: number; guardian_name: string; relationship: string; authorization_status: string }
      | undefined;

    if (!guardian) {
      res.status(404).json({ error: 'Selected guardian is not registered for this student.' });
      return;
    }

    const today = getTodayDate();
    const pickupTime = getCurrentTimeFormatted();

    // STRICT SAFETY CHECK: Reject unauthorized guardian pickup & alert parent
    if (guardian.authorization_status !== 'Authorized') {
      if (recordRejectedAttempt) {
        db.prepare(`
          INSERT INTO pickup (student_id, guardian_id, guard_id, guard_name, pickup_date, pickup_time, verification_status, notes)
          VALUES (?, ?, ?, ?, ?, ?, 'Rejected', ?)
        `).run(
          student.student_id,
          guardian.id,
          req.user!.id,
          req.user!.fullName,
          today,
          pickupTime,
          notes?.trim() || 'Unauthorized guardian pickup attempt blocked at gate'
        );
      }

      createParentNotification({
        studentId: student.student_id,
        parentName: student.parent_name,
        parentContact: student.parent_contact,
        eventType: 'Security Alert',
        channel: 'SMS',
        message: `SECURITY ALERT for ${student.parent_name}: An unauthorized pickup attempt for ${student.student_name} (${student.student_id}) by ${guardian.guardian_name} (${guardian.relationship}) was blocked at the gate on ${today} at ${pickupTime}.`,
        sentDate: today,
        sentTime: pickupTime,
      });

      res.status(403).json({
        error: `Pickup Rejected: ${guardian.guardian_name} (${guardian.relationship}) is UNAUTHORIZED. Student release is strictly prohibited. Security alert sent to ${student.parent_name} (${student.parent_contact}).`,
      });
      return;
    }

    const alreadyPickedUp = db
      .prepare("SELECT * FROM pickup WHERE student_id = ? AND pickup_date = ? AND verification_status = 'Verified'")
      .get(student.student_id, today) as { pickup_time: string } | undefined;

    if (alreadyPickedUp) {
      res.status(409).json({
        error: `${student.student_name} was already picked up today at ${alreadyPickedUp.pickup_time}.`,
      });
      return;
    }

    const info = db
      .prepare(`
        INSERT INTO pickup (student_id, guardian_id, guard_id, guard_name, pickup_date, pickup_time, verification_status, notes)
        VALUES (?, ?, ?, ?, ?, ?, 'Verified', ?)
      `)
      .run(
        student.student_id,
        guardian.id,
        req.user!.id,
        req.user!.fullName,
        today,
        pickupTime,
        notes?.trim() || 'Authorized guardian verified by gate officer'
      );

    const pickup = db
      .prepare(`
        SELECT p.*, s.student_name, s.class_name, g.guardian_name, g.relationship
        FROM pickup p
        JOIN students s ON p.student_id = s.student_id
        JOIN guardians g ON p.guardian_id = g.id
        WHERE p.id = ?
      `)
      .get(info.lastInsertRowid);

    const notification = createParentNotification({
      studentId: student.student_id,
      parentName: student.parent_name,
      parentContact: student.parent_contact,
      eventType: 'Pickup',
      channel: 'SMS',
      message: `Assalam-o-Alaikum ${student.parent_name}, ${student.student_name} (${student.student_id}, ${student.class_name}) has been safely picked up by ${guardian.guardian_name} (${guardian.relationship}) on ${today} at ${pickupTime}.`,
      sentDate: today,
      sentTime: pickupTime,
    });

    res.status(201).json({
      message: `Pickup confirmed: ${student.student_name} released to ${guardian.guardian_name} (${guardian.relationship}) at ${pickupTime}. Parent notified (${student.parent_contact}).`,
      pickup,
      notification,
    });
  });

  // =========================================================
  // 7. REPORTS ROUTE
  // =========================================================
  app.get('/api/reports', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const date = String(req.query.date || getTodayDate()).trim();

    const allStudents = db.prepare('SELECT * FROM students ORDER BY class_name ASC, roll_number ASC').all() as Array<{
      id: number;
      student_id: string;
      student_name: string;
      class_name: string;
      roll_number: string;
      parent_name: string;
      parent_contact: string;
      qr_code_data: string;
      created_at: string;
    }>;

    const presentStudents = db
      .prepare(`
        SELECT a.id, a.student_id, s.student_name, s.class_name, s.roll_number,
               a.attendance_date, a.arrival_time, a.status, u.full_name as marked_by_name, a.created_at
        FROM attendance a
        JOIN students s ON a.student_id = s.student_id
        LEFT JOIN users u ON a.marked_by = u.id
        WHERE a.attendance_date = ? AND a.status = 'Present'
        ORDER BY a.arrival_time ASC
      `)
      .all(date) as Array<{ student_id: string }>;

    const presentIds = new Set(presentStudents.map((r) => r.student_id));
    const absentStudents = allStudents.filter((s) => !presentIds.has(s.student_id));

    const pickupRecords = db
      .prepare(`
        SELECT p.*, s.student_name, s.class_name, g.guardian_name, g.relationship
        FROM pickup p
        JOIN students s ON p.student_id = s.student_id
        JOIN guardians g ON p.guardian_id = g.id
        WHERE p.pickup_date = ?
        ORDER BY p.id DESC
      `)
      .all(date);

    const totalStudents = allStudents.length;
    const presentCount = presentStudents.length;
    const absentCount = absentStudents.length;
    const attendanceRate = totalStudents > 0 ? Math.round((presentCount / totalStudents) * 100) : 0;

    res.json({
      date,
      summary: {
        totalStudents,
        presentCount,
        absentCount,
        pickupCount: pickupRecords.length,
        attendanceRate,
      },
      presentStudents,
      absentStudents,
      pickupRecords,
    });
  });

  // =========================================================
  // 8. PARENT NOTIFICATIONS ROUTES
  // =========================================================
  app.get('/api/notifications', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const q = String(req.query.q || '').trim();
    const date = String(req.query.date || '').trim();
    const eventType = String(req.query.eventType || '').trim();

    let sql = `
      SELECT n.*, s.student_name, s.class_name
      FROM notifications n
      JOIN students s ON n.student_id = s.student_id
    `;
    const params: string[] = [];
    const clauses: string[] = [];

    if (date) {
      clauses.push('n.sent_date = ?');
      params.push(date);
    }
    if (eventType) {
      clauses.push('n.event_type = ?');
      params.push(eventType);
    }
    if (q) {
      clauses.push('(s.student_name LIKE ? OR n.student_id LIKE ? OR n.parent_name LIKE ? OR n.message LIKE ?)');
      const pat = `%${q}%`;
      params.push(pat, pat, pat, pat);
    }

    if (clauses.length > 0) {
      sql += ' WHERE ' + clauses.join(' AND ');
    }
    sql += ' ORDER BY n.sent_date DESC, n.id DESC';

    const notifications = db.prepare(sql).all(...params);
    res.json({ notifications });
  });

  app.post('/api/notifications', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const { studentId, grade, eventType, channel, message } = req.body as {
      studentId?: string;
      grade?: string;
      eventType?: 'Arrival' | 'Pickup' | 'Security Alert' | 'Absence' | 'General';
      channel?: 'SMS' | 'WhatsApp' | 'App Alert';
      message?: string;
    };

    if (!message?.trim()) {
      res.status(400).json({ error: 'Notification message cannot be empty.' });
      return;
    }

    const validEvent = eventType && ['Arrival', 'Pickup', 'Security Alert', 'Absence', 'General'].includes(eventType)
      ? eventType
      : 'General';
    const validChannel = channel && ['SMS', 'WhatsApp', 'App Alert'].includes(channel)
      ? channel
      : 'SMS';

    let targetStudents: Array<{
      student_id: string;
      student_name: string;
      class_name: string;
      parent_name: string;
      parent_contact: string;
    }> = [];

    if (studentId?.trim()) {
      const stu = db
        .prepare('SELECT student_id, student_name, class_name, parent_name, parent_contact FROM students WHERE student_id = ?')
        .get(studentId.trim().toUpperCase()) as (typeof targetStudents)[number] | undefined;
      if (!stu) {
        res.status(404).json({ error: 'Selected student not found.' });
        return;
      }
      targetStudents = [stu];
    } else if (grade?.trim() && grade.trim() !== 'ALL') {
      targetStudents = db
        .prepare('SELECT student_id, student_name, class_name, parent_name, parent_contact FROM students WHERE class_name = ?')
        .all(grade.trim()) as typeof targetStudents;
    } else {
      targetStudents = db
        .prepare('SELECT student_id, student_name, class_name, parent_name, parent_contact FROM students')
        .all() as typeof targetStudents;
    }

    if (targetStudents.length === 0) {
      res.status(404).json({ error: 'No students found for the selected target.' });
      return;
    }

    const sentDate = getTodayDate();
    const sentTime = getCurrentTimeFormatted();
    const createdList = targetStudents.map((stu) => {
      const personalized = message
        .trim()
        .replace(/\{student\}/gi, stu.student_name)
        .replace(/\{parent\}/gi, stu.parent_name)
        .replace(/\{grade\}/gi, stu.class_name);
      return createParentNotification({
        studentId: stu.student_id,
        parentName: stu.parent_name,
        parentContact: stu.parent_contact,
        eventType: validEvent,
        channel: validChannel,
        message: personalized,
        sentDate,
        sentTime,
      });
    });

    res.status(201).json({
      message: `Parent notification sent to ${createdList.length} ${createdList.length === 1 ? 'parent' : 'parents'} via ${validChannel}.`,
      notifications: createdList,
    });
  });

  app.post('/api/notifications/send-absent', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res: Response) => {
    const targetDate = String((req.body as { date?: string })?.date || getTodayDate()).trim();
    const sentTime = getCurrentTimeFormatted();

    const absentStudents = db
      .prepare(`
        SELECT s.student_id, s.student_name, s.class_name, s.parent_name, s.parent_contact
        FROM students s
        WHERE s.student_id NOT IN (
          SELECT attendance_date_att.student_id FROM attendance attendance_date_att
          WHERE attendance_date_att.attendance_date = ? AND attendance_date_att.status = 'Present'
        )
        AND s.student_id NOT IN (
          SELECT n.student_id FROM notifications n
          WHERE n.sent_date = ? AND n.event_type = 'Absence'
        )
      `)
      .all(targetDate, targetDate) as Array<{
      student_id: string;
      student_name: string;
      class_name: string;
      parent_name: string;
      parent_contact: string;
    }>;

    if (absentStudents.length === 0) {
      res.json({
        message: `All absent students' parents for ${targetDate} have already been notified (or all students are Present).`,
        count: 0,
        notifications: [],
      });
      return;
    }

    const createdList = absentStudents.map((stu) =>
      createParentNotification({
        studentId: stu.student_id,
        parentName: stu.parent_name,
        parentContact: stu.parent_contact,
        eventType: 'Absence',
        channel: 'SMS',
        message: `Assalam-o-Alaikum ${stu.parent_name}, your child ${stu.student_name} (${stu.student_id}, ${stu.class_name}) has not checked in at school today (${targetDate}). Please contact the school office if needed.`,
        sentDate: targetDate,
        sentTime,
      })
    );

    res.status(201).json({
      message: `Absence alerts sent to ${createdList.length} ${createdList.length === 1 ? 'parent' : 'parents'} for ${targetDate}.`,
      count: createdList.length,
      notifications: createdList,
    });
  });

  app.delete('/api/notifications/:id', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT id FROM notifications WHERE id = ?').get(id);
    if (!existing) {
      res.status(404).json({ error: 'Notification record not found.' });
      return;
    }
    db.prepare('DELETE FROM notifications WHERE id = ?').run(id);
    res.json({ message: 'Notification log deleted.' });
  });

  // =========================================================
  // 8. DOWNLOADABLE PHP + MYSQL + XAMPP PACKAGE
  // =========================================================
  app.get('/api/download-php-project', (_req: Request, res: Response) => {
    const phpDir = path.resolve(process.cwd(), 'php-xampp-project');
    if (!fs.existsSync(phpDir)) {
      res.status(404).json({ error: 'PHP XAMPP project folder not found.' });
      return;
    }

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="smart-school-xampp-php-project.zip"');

    const archive = new ZipArchive({ zlib: { level: 9 } });
    archive.on('error', (err: Error) => {
      res.status(500).send({ error: err.message });
    });
    archive.pipe(res);
    archive.directory(phpDir, 'smart_school_system');
    archive.finalize();
  });

  // =========================================================
  // VITE DEV / PRODUCTION STATIC MIDDLEWARE
  // =========================================================
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Smart School Attendance & Student Safety System running at http://localhost:${PORT}`);
  });
}

startServer();
