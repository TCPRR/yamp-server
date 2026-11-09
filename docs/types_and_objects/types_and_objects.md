# Types & Objects
In the yampd there are a few primary ways a function can output

"Objects" are heap objects, fields all in the heap, and meant to be freed with a pairing free function that also frees the heap
"Inline Objects" are objects except not necessarily in the heap, these are meant to be only having their fields freed
"JSON" is the JSON object meant to go out, since cJSON internally duplicates strings, you can safely take a ptr and output JSON, then free the object depending on origin