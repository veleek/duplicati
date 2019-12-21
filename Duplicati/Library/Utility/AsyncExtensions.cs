using System;
using System.Threading;
using System.Threading.Tasks;

namespace Duplicati.Library.Utility
{
    /// <summary>
    /// Extension methods to provide additional Async/Await functionality for various objects.
    /// </summary>
    public static class AsyncExtensions
    {
        /// <summary>
        /// Allows asynchronously waiting on a WaitHandle with an optional delay
        /// </summary>
        /// <param name="waitHandle">The handle to wait on.</param>
        /// <param name="delay">The duration to wait for the handled to be signaled.  If null is provided then the timeout never elapses.</param>
        /// <returns>A task that completes when the WaitHandle is signaled or the delay elapses.</returns>
        /// <remarks>
        /// Modified slightly from the MSDN documentation on handled WaitHandles in async code.
        /// https://docs.microsoft.com/en-us/dotnet/standard/asynchronous-programming-patterns/interop-with-other-asynchronous-patterns-and-types#from-wait-handles-to-tap
        /// </remarks>
        public static Task WaitOneAsync(this WaitHandle waitHandle, TimeSpan? delay = null)
        {
            if (waitHandle == null)
                throw new ArgumentNullException("waitHandle");

            var tcs = new TaskCompletionSource<bool>();
            var rwh = ThreadPool.RegisterWaitForSingleObject(waitHandle,
                delegate { tcs.TrySetResult(true); }, null, delay ?? Timeout.InfiniteTimeSpan, true);
            var t = tcs.Task;
            t.ContinueWith((antecedent) => rwh.Unregister(null));
            return t;
        }

        /// <summary>
        /// Allows asynchronously waiting on for a CancellationToken to be cancelled.
        /// </summary>
        /// <param name="cancellationToken">The token to wait on.</param>
        /// <param name="delay">The duration to wait for cancellation for.  If 0 is provided, then the cancellation token will be checked and 
        /// immediately return.  If null is provided then the timout never elapses.</param>
        /// <returns>A task that completes when the cancellation token is cancelled or the delay elapses.</returns>
        public static async Task WhenCancelled(this CancellationToken cancellationToken, TimeSpan? delay = null)
        {
            if (cancellationToken == CancellationToken.None)
            {
                throw new InvalidOperationException("CancellationToken.None will never be cancelled");
            }

            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            int delayMs= (int?)delay?.TotalMilliseconds ?? Timeout.Infinite;
            if(delayMs == 0)
            {
                return;
            }

            TaskCompletionSource<bool> tcs = new TaskCompletionSource<bool>();
            using (cancellationToken.Register(() => tcs.TrySetResult(true)))
            {
                if (delayMs == Timeout.Infinite)
                {
                    await tcs.Task;
                }
                else
                {
                    await Task.WhenAny(tcs.Task, Task.Delay(delayMs));
                }
            }
        }
    }
}
