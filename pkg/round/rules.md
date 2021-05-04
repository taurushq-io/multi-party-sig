# Validation rules 

## ProcessMessage(msg)

### Expected
- Type 
- BroadcastMethod (reliable/all/perso)
- 

- Type 
- From 
- To
- Broadcast
- Content

1. `Type`/`Content` ok? (`msg.IsValid()`)
1. `From` != self
1. `To`/`Broadcast`
    1. `To` != 0 => `To` == self
    1. `To` == 0 => 
        1. `Broadcast` => Verify
    


## Party 

- store all pb.Messages
- store errors ?