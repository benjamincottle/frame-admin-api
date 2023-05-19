use lazy_static::lazy_static;
use serde::Serialize;

use crate::gphotos_api::MediaItem;

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Condvar, Mutex},
};

lazy_static! {
    pub static ref TASK_BOARD: Mutex<TaskBoard> = {
        let task_board = TaskBoard {
            tasks: BTreeMap::new(),
            next_task_id: 0,
        };
        log::info!("task board created");
        Mutex::new(task_board)
    };
}

impl TASK_BOARD {
    #[allow(unused_must_use)]
    pub fn initialise(&self) {
        self.lock().unwrap();
    }

    pub fn get_board(&self) -> TaskBoard {
        let task_board = self.lock().unwrap();
        task_board.clone()
    }

    pub fn board_status(&self) -> Result<TaskBoardStatus, String> {
        let task_board = self
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;
        let (pending_count, in_progress_count, completed_count, failed_count) = task_board
            .tasks
            .values()
            .fold((0, 0, 0, 0), |counts, task| match task.status {
                Status::Pending => (counts.0 + 1, counts.1, counts.2, counts.3),
                Status::InProgress => (counts.0, counts.1 + 1, counts.2, counts.3),
                Status::Completed => (counts.0, counts.1, counts.2 + 1, counts.3),
                Status::Failed => (counts.0, counts.1, counts.2, counts.3 + 1),
            });
        let total_steps = task_board.tasks.len() * 3;
        let current_step =
            pending_count + 2 * in_progress_count + 3 * (completed_count + failed_count);
        println!(
            "[Debug] Task Dashboard: total_steps: {}, current_step: {}, failed_count: {}",
            total_steps, current_step, failed_count
        );
        Ok(TaskBoardStatus {
            total_steps,
            current_step,
            failed_count,
        })
    }

    pub fn add_task(&self, action: Action) -> TaskId {
        let mut task_board = self.lock().unwrap();
        task_board.next_task_id += 1;
        let task_id = task_board.next_task_id;
        task_board.tasks.insert(
            task_id,
            BoardData {
                action,
                status: Status::Pending,
            },
        );
        task_board.next_task_id
    }

    pub fn set_board_data(&self, task_id: TaskId, status: Status) {
        let mut task_board = self.lock().unwrap();
        if let Some(task) = task_board.tasks.get_mut(&task_id) {
            task.status = status;
        }
    }

    pub fn reset(&self) {
        let mut task_board = self.lock().unwrap();
        task_board.next_task_id = 0;
        task_board.tasks.clear();
    }

    pub fn dump(&self) {
        let task_board = self.lock().unwrap();
        println!("[Debug] Task Dashboard:");
        println!("[Debug]   Tasks:");
        for task in task_board.tasks.iter() {
            println!(
                "[Debug]     task_id: {:?}, action {:?}, status: {:?}",
                task.0, task.1.action, task.1.status
            );
        }
        println!("[Debug] next_task_id: {}", task_board.next_task_id);
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Status {
    Pending,
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub enum Action {
    Add,
    Remove,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskBoardStatus {
    total_steps: usize,
    current_step: usize,
    failed_count: usize,
}

#[derive(Debug)]
pub enum TaskData {
    MediaItem(MediaItem),
    String(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskBoard {
    tasks: BTreeMap<TaskId, BoardData>,
    next_task_id: TaskId,
}

#[derive(Debug, Clone, Serialize)]
pub struct BoardData {
    pub action: Action,
    pub status: Status,
}

// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
// pub struct TaskId(pub usize);
type TaskId = usize;

#[derive(Debug)]
pub struct Task {
    pub id: TaskId,
    pub action: Action,
    pub data: TaskData,
    pub status: Status,
}

#[derive(Debug)]
pub struct TaskQueue {
    data: Mutex<VecDeque<Task>>,
    cv: Condvar,
}

impl TaskQueue {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        }
    }

    pub fn push(&self, task: Task) {
        let mut data = self.data.lock().unwrap();
        data.push_back(task);
        self.cv.notify_one();
    }

    pub fn pop(&self) -> Task {
        let mut data = self.data.lock().unwrap();
        while data.is_empty() {
            data = self.cv.wait(data).unwrap();
        }
        data.pop_front().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        let data = self.data.lock().unwrap();
        data.is_empty()
    }
}
