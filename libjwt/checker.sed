s/FUNC(\([^)]*\))/jwt_checker_\1/
s/jwt_common_t/jwt_checker_t/g
s/CLAIMS_DEF/(JWT_CLAIM_EXP\|JWT_CLAIM_NBF)/g
s/.*XXX.*/\/\* XXX This file is generated, do not edit! \*\//
s/__DISABLE/-1/
/#ifdef JWT_BUILDER/,/#endif/d
/#ifdef/d
/#endif/d
