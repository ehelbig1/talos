use async_nats::jetstream::Message;

async fn test(msg: &Message) {
    let _ = msg.ack().await;
}
