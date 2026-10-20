use std::time::Duration;

use qbase::{
    Cancelled,
    time::{IdleSince, Timeout, timer::*},
};
use tokio::time::Instant;

fn now() -> Instant {
    Instant::now()
}

#[test]
fn timeout_after_checks_elapsed_time_including_the_deadline() {
    let start = Instant::now();
    let duration = Duration::from_secs(10);
    assert!(!IdleSince::new().timeout_after(start + duration, duration));
    let idle = IdleSince::with_instant(start);
    assert!(!idle.timeout_after(start, duration));
    assert!(idle.timeout_after(start + duration, duration));
    assert!(idle.timeout_after(start + duration * 2, duration));
}

#[test]
fn expires_in_saturates_at_zero_after_the_deadline() {
    let start = Instant::now();
    let duration = Duration::from_secs(10);
    let idle = IdleSince::with_instant(start);
    assert_eq!(idle.expires_in(start, duration), duration);
    assert_eq!(
        idle.expires_in(start + duration / 2, duration),
        duration / 2
    );
    assert_eq!(idle.expires_in(start + duration, duration), Duration::ZERO);
    assert_eq!(
        idle.expires_in(start + duration * 2, duration),
        Duration::ZERO
    );
}

#[test]
fn expires_in_handles_unrepresentable_deadlines() {
    let start = Instant::now();
    let idle = IdleSince::with_instant(start);
    assert_eq!(idle.expires_in(start, Duration::MAX), Duration::MAX);
    assert_eq!(
        idle.expires_in(start + Duration::from_secs(1), Duration::MAX),
        Duration::MAX - Duration::from_secs(1)
    );
}

#[tokio::test(start_paused = true)]
async fn no_activity_waits_until_first_activity_starts_the_deadline() {
    let timer = ArcIdleTimer::new(Duration::from_secs(5));
    let start = now();
    let waiter = timer.clone().timeout();
    tokio::pin!(waiter);
    assert!(futures::poll!(&mut waiter).is_pending());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(futures::poll!(&mut waiter).is_pending());
    assert!(timer.on_sent_at(now()).unwrap().unwrap());
    assert!(matches!(waiter.await, Ok(Timeout)));
    assert_eq!(now() - start, Duration::from_secs(15));
}

#[tokio::test(start_paused = true)]
async fn zero_max_idle_timeout_disables_expiry() {
    let timer = ArcIdleTimer::new(Duration::ZERO);
    assert!(timer.on_sent_at(now()).unwrap().unwrap());
    let waiter = timer.clone().timeout();
    tokio::pin!(waiter);
    assert!(futures::poll!(&mut waiter).is_pending());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(futures::poll!(&mut waiter).is_pending());
    assert!(timer.on_rcvd_at(now()).unwrap().unwrap());
    assert!(timer.on_sent_at(now()).unwrap().unwrap());
    timer.cancel();
    assert!(matches!(waiter.await, Err(Cancelled)));
}

#[tokio::test(start_paused = true)]
async fn cancellation_is_observed_without_activity() {
    let timer = ArcIdleTimer::new(Duration::from_secs(5));
    let waiter = timer.clone().timeout();
    tokio::pin!(waiter);
    assert!(futures::poll!(&mut waiter).is_pending());
    timer.cancel();
    let start = now();
    assert!(matches!(waiter.await, Err(Cancelled)));
    assert_eq!(now() - start, Duration::from_millis(100));
}

#[tokio::test(start_paused = true)]
async fn connection_expires_at_max_idle_timeout_without_an_extra_phase() {
    let timer = ArcIdleTimer::new(Duration::from_secs(5));
    let start = now();
    assert!(timer.on_rcvd_at(start).unwrap().unwrap());
    assert!(matches!(timer.timeout().await, Ok(Timeout)));
    assert_eq!(now() - start, Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn repeated_sends_without_receiving_do_not_extend_timeout() {
    let timer = ArcIdleTimer::new(Duration::from_secs(5));
    let start = now();
    assert!(timer.on_sent_at(start).unwrap().unwrap());
    for _ in 0..4 {
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!timer.on_sent_at(now()).unwrap().unwrap());
    }
    assert!(matches!(timer.clone().timeout().await, Ok(Timeout)));
    assert_eq!(now() - start, Duration::from_secs(5));
    assert!(matches!(timer.on_sent_at(now()), Ok(Err(Timeout))));
}

#[tokio::test(start_paused = true)]
async fn receive_extends_timeout_and_rearms_only_one_send() {
    let timer = ArcIdleTimer::new(Duration::from_secs(10));
    let start = now();
    assert!(timer.on_sent_at(start).unwrap().unwrap());
    let (result, ()) = tokio::join!(timer.clone().timeout(), async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(timer.on_rcvd_at(now()).unwrap().unwrap());
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(timer.on_sent_at(now()).unwrap().unwrap());
        tokio::time::sleep(Duration::from_secs(9)).await;
        assert!(!timer.on_sent_at(now()).unwrap().unwrap());
    });
    assert!(matches!(result, Ok(Timeout)));
    assert_eq!(now() - start, Duration::from_secs(18));
}

#[tokio::test(start_paused = true)]
async fn late_wait_returns_timeout_without_sleeping() {
    let timer = ArcIdleTimer::new(Duration::from_secs(5));
    assert!(timer.on_sent_at(now()).unwrap().unwrap());
    tokio::time::advance(Duration::from_secs(20)).await;
    let start = now();
    assert!(matches!(timer.timeout().await, Ok(Timeout)));
    assert_eq!(now(), start);
}

#[tokio::test(start_paused = true)]
async fn sleep_rechecks_receive_activity() {
    let timer = ArcIdleTimer::new(Duration::from_secs(5));
    let start = now();
    assert!(timer.on_sent_at(start).unwrap().unwrap());
    let (result, ()) = tokio::join!(timer.clone().timeout(), async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(timer.on_rcvd_at(now()).unwrap().unwrap());
    });
    assert!(matches!(result, Ok(Timeout)));
    assert_eq!(now() - start, Duration::from_secs(7));
}

#[tokio::test]
async fn shared_activity_distinguishes_updates_expiry_and_cancellation() {
    let timer = ArcIdleTimer::new(Duration::from_secs(10));
    let start = Instant::now();
    assert!(matches!(timer.on_sent_at(start), Ok(Ok(true))));
    assert!(matches!(timer.on_sent_at(start), Ok(Ok(false))));
    assert!(matches!(
        timer.on_rcvd_at(start + Duration::from_secs(10)),
        Ok(Err(Timeout))
    ));
    timer.cancel();
    assert!(matches!(
        timer.on_rcvd_at(start + Duration::from_secs(11)),
        Err(Cancelled)
    ));
}

#[tokio::test]
async fn cancelling_before_wait_is_permanent() {
    let timer = ArcIdleTimer::new(Duration::from_secs(10));
    timer.cancel();
    timer.cancel();
    assert!(timer.on_sent_at(Instant::now()).is_err());
    assert!(timer.on_rcvd_at(Instant::now()).is_err());
    assert!(matches!(timer.timeout().await, Err(Cancelled)));
}

#[tokio::test(start_paused = true)]
async fn cancellation_is_observed_when_the_current_sleep_finishes() {
    let timer = ArcIdleTimer::new(Duration::from_secs(10));
    let start = now();
    assert!(timer.on_sent_at(start).unwrap().unwrap());
    let task = tokio::spawn(timer.clone().timeout());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    timer.cancel();
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    assert!(matches!(task.await.unwrap(), Err(Cancelled)));
    assert_eq!(now() - start, Duration::from_secs(10));
}

#[tokio::test(start_paused = true)]
async fn unrepresentable_deadline_does_not_panic() {
    let timer = ArcIdleTimer::new(Duration::MAX);
    assert!(timer.on_sent_at(now()).unwrap().unwrap());
    let waiter = timer.clone().timeout();
    tokio::pin!(waiter);
    assert!(futures::poll!(&mut waiter).is_pending());
    assert!(timer.on_rcvd_at(now()).unwrap().unwrap());
    assert!(futures::poll!(&mut waiter).is_pending());
}
