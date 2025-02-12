s/FUNC(\([^)]*\))/jwt_builder_\1/
s/jwt_common_t/jwt_builder_t/g
s/CLAIMS_DEF/JWT_CLAIM_IAT/g
s/.*XXX.*/\/\* XXX This file is generated, do not edit! \*\//
s/__DISABLE/0/
/#ifdef JWT_CHECKER/,/#endif/d
/#ifdef/d
/#endif/d
