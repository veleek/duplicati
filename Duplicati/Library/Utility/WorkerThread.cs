#region Disclaimer / License
// Copyright (C) 2015, The Duplicati Team
// http://www.duplicati.com, info@duplicati.com
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
// 
#endregion
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Duplicati.Library.Utility
{
    /// <summary>
    /// Class to encapsulate a thread that runs a list of queued operations
    /// </summary>
    /// <typeparam name="Tx">The type to operate on</typeparam>
    public class WorkerThread<Tx> where Tx : class
    {
        /// <summary>
        /// Locking object for shared data
        /// </summary>
        private readonly object m_lock = new object();
        /// <summary>
        /// The wait event
        /// </summary>
        private readonly AutoResetEvent m_event;
        /// <summary>
        /// The internal list of tasks to perform
        /// </summary>
        private ConcurrentQueue<Tx> m_tasks;
        /// <summary>
        /// A flag used to terminate the thread
        /// </summary>
        private CancellationTokenSource m_cancellationTokenSource;
        /// <summary>
        /// The coordinating thread
        /// </summary>
        private Task m_runnerTask;

        /// <summary>
        /// A value indicating if the coordinating thread is running
        /// </summary>
        private volatile bool m_active;

        /// <summary>
        /// The current task being processed
        /// </summary>
        private Tx m_currentTask;
        /// <summary>
        /// A callback that performs the actual work on the item
        /// </summary>
        private readonly Action<Tx> m_delegate;

        /// <summary>
        /// An event that is raised when the runner state changes
        /// </summary>
        public event Action<WorkerThread<Tx>, RunState> WorkerStateChanged;
        /// <summary>
        /// Event that occurs when a new operation is being processed
        /// </summary>
        public event Action<WorkerThread<Tx>, Tx> StartingWork;
        /// <summary>
        /// Event that occurs when an operation has completed
        /// </summary>
        public event Action<WorkerThread<Tx>, Tx> CompletedWork;
        /// <summary>
        /// Event that occurs when an error is detected
        /// </summary>
        public event Action<WorkerThread<Tx>, Tx, Exception> OnError;
        /// <summary>
        /// An evnet that occurs when a new task is added to the queue or an existing one is removed
        /// </summary>
        public event Action<WorkerThread<Tx>> WorkQueueChanged;

        /// <summary>
        /// The internal state
        /// </summary>
        private volatile RunState m_state;

        /// <summary>
        /// The states the scheduler can take
        /// </summary>
        public enum RunState
        {
            /// <summary>
            /// The program is running as normal
            /// </summary>
            Run,
            /// <summary>
            /// The program is suspended by the user
            /// </summary>
            Paused
        }

        /// <summary>
        /// Constructs a new WorkerThread
        /// </summary>
        /// <param name="item">The callback that performs the work</param>
        public WorkerThread(Action<Tx> item, bool paused)
        {
            m_delegate = item;
            m_event = new AutoResetEvent(paused);
            m_tasks = new ConcurrentQueue<Tx>();
            m_state = paused ? RunState.Paused : RunState.Run;

            m_cancellationTokenSource = new CancellationTokenSource();
            CancellationToken cancellationToken = m_cancellationTokenSource.Token;
            m_runnerTask = Task.Run(() => Runner(cancellationToken), cancellationToken);
        }

        /// <summary>
        /// Gets a copy of the current queue
        /// </summary>
        public List<Tx> CurrentTasks
        {
            get
            {
                return new List<Tx>(m_tasks.ToArray());
            }

        }

        /// <summary>
        /// Gets the current run state
        /// </summary>
        private void SetState(RunState value)
        {
            m_state = value;
            m_event.Set();
        }

        /// <summary>
        /// Gets a value indicating if the worker is running
        /// </summary>
        public bool Active
        {
            get { return m_active; }
        }

        /// <summary>
        /// Adds a task to the queue
        /// </summary>
        /// <param name="task">The task to add</param>
        public void AddTask(Tx task)
        {
            m_tasks.Enqueue(task);
            m_event.Set();

            WorkQueueChanged?.Invoke(this);
        }

        /// <summary>
        /// An overloaded AddTask method that allows a task to skip to the front of a queue
        /// It does this by creating a new queue, adding the new task first, and then adding
        /// all the old tasks to the new queue. It's cleaner to use a linked list,
        /// but the performance difference is negligible on such a small queue.
        /// </summary>
        /// <param name="task">Task.</param>
        /// <param name="skipQueue">If set to <c>true</c> skip queue.</param>
        public void AddTask(Tx task, bool skipQueue)
        {
            if (!skipQueue) {
                // Fall back to default AddTask method
                AddTask(task);
                return;
            }

            ConcurrentQueue<Tx> newQueue = new ConcurrentQueue<Tx>();
            newQueue.Enqueue(task);

            var oldTasks = m_tasks;
            m_tasks = newQueue;

            while (oldTasks.TryDequeue(out Tx n))
            {
                m_tasks.Enqueue(n);
            }

            m_event.Set();

            WorkQueueChanged?.Invoke(this);
        }

        /// <summary>
        /// This will clear the pending queue
        /// <param name="cancelTask">True if the current running task should be cancelled</param>
        /// </summary>
        public void ClearQueue(bool cancelTask)
        {
            m_tasks = new ConcurrentQueue<Tx>();

            if (cancelTask)
            {   
                try
                {
                    m_cancellationTokenSource.Cancel();
                    m_runnerTask.Wait(500);
                }
                catch
                {
                }

                m_cancellationTokenSource = new CancellationTokenSource();
                CancellationToken cancellationToken = m_cancellationTokenSource.Token;
                m_runnerTask = Task.Run(() => Runner(cancellationToken), cancellationToken);
            }
        }

        /// <summary>
        /// Gets a reference to the currently executing task.
        /// BEWARE: This is not protected by a mutex, DO NOT MODIFY IT!!!!
        /// </summary>
        public Tx CurrentTask
        {
            get
            {
                return m_currentTask;
            }
        }

        /// <summary>
        /// Terminates the thread. Any items still in queue will be removed
        /// </summary>
        /// <param name="wait">True if the call should block until the thread has exited, false otherwise</param>
        public void Terminate(bool wait)
        {
            m_cancellationTokenSource.Cancel();
            m_event.Set();

            if (wait)
                m_runnerTask.Wait();
        }

        /// <summary>
        /// This is the thread entry point
        /// </summary>
        private async Task Runner(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (m_state != RunState.Run)
                {
                    await WaitForRunState(cancellationToken);
                    continue;
                }

                if (!m_tasks.TryDequeue(out m_currentTask))
                {
                    await m_event.WaitOneAsync();
                    continue;
                };

                StartingWork?.Invoke(this, m_currentTask);

                try
                {
                    m_active = true;
                    m_delegate(m_currentTask);
                }
                catch (Exception ex)
                {
                    if (OnError != null)
                    {
                        try { OnError(this, m_currentTask, ex); }
                        catch { }
                    }
                }
                finally
                {
                    m_active = false;
                }

                var task = m_currentTask;
                m_currentTask = null;

                try 
                {
                    CompletedWork?.Invoke(this, task);
                }
                catch (Exception ex)
                {
                    try { OnError(this, task, ex); }
                    catch { }
                }
            }
        }

        private async Task WaitForRunState(CancellationToken cancellationToken)
        {
            WorkerStateChanged?.Invoke(this, m_state);

            //Sleep for brief periods, until signaled
            while (!cancellationToken.IsCancellationRequested && m_state != RunState.Run)
            {
                await Task.WhenAny(
                    cancellationToken.WhenCancelled(),
                    m_event.WaitOneAsync(TimeSpan.FromMinutes(5))
                );
            }

            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            //If we were not terminated, we are now ready to run
            WorkerStateChanged?.Invoke(this, m_state);
        }

        /// <summary>
        /// Instructs Duplicati to run scheduled backups
        /// </summary>
        public void Resume()
        {
            SetState(RunState.Run);
        }

        /// <summary>
        /// Instructs Duplicati to pause scheduled backups
        /// </summary>
        public void Pause()
        {
            SetState(RunState.Paused);
        }
    }
}
