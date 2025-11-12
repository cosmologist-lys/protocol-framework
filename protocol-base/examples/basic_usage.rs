fn main() {
    let result: protocol_base::ProtocolResult<()> = Ok(());
    println!("{:?}", result);
    
    let error = protocol_base::ProtocolError::CommonError("test".to_string());
    println!("{:?}", error);
}
