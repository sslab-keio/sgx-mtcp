/* Driver template for the LEMON parser generator.
** The author disclaims copyright to this source code.
*/
/* First off, code is include which follows the "include" declaration
** in the input file. */
#include <stdio.h>
#line 6 "./mod_ssi_exprparser.y"

#include "mod_ssi_expr.h"
#include "buffer.h"

#include <assert.h>
#include <string.h>

#ifdef COMPILE_WITH_INTEL_SGX
#include "enclaveshim_ocalls.h"
#else
#define my_printf(format, ...) printf(format, ##__VA_ARGS__)
#define my_fprintf(stream, format, ...) fprintf(stream, format, ##__VA_ARGS__)
#endif

#line 16 "mod_ssi_exprparser.c"
/* Next is all token values, in a form suitable for use by makeheaders.
** This section will be null unless lemon is run with the -m switch.
*/
/*
** These constants (all generated automatically by the parser generator)
** specify the various kinds of tokens (terminals) that the parser
** understands.
**
** Each symbol here is a terminal symbol in the grammar.
*/
/* Make sure the INTERFACE macro is defined.
*/
#ifndef INTERFACE
# define INTERFACE 1
#endif
/* The next thing included is series of defines which control
** various aspects of the generated parser.
**    YYCODETYPE         is the data type used for storing terminal
**                       and nonterminal numbers.  "unsigned char" is
**                       used if there are fewer than 250 terminals
**                       and nonterminals.  "int" is used otherwise.
**    YYNOCODE           is a number of type YYCODETYPE which corresponds
**                       to no legal terminal or nonterminal number.  This
**                       number is used to fill in empty slots of the hash
**                       table.
**    YYFALLBACK         If defined, this indicates that one or more tokens
**                       have fall-back values which should be used if the
**                       original value of the token will not parse.
**    YYACTIONTYPE       is the data type used for storing terminal
**                       and nonterminal numbers.  "unsigned char" is
**                       used if there are fewer than 250 rules and
**                       states combined.  "int" is used otherwise.
**    ssiexprparserTOKENTYPE     is the data type used for minor tokens given
**                       directly to the parser from the tokenizer.
**    YYMINORTYPE        is the data type used for all minor tokens.
**                       This is typically a union of many types, one of
**                       which is ssiexprparserTOKENTYPE.  The entry in the union
**                       for base tokens is called "yy0".
**    YYSTACKDEPTH       is the maximum depth of the parser's stack.
**    ssiexprparserARG_SDECL     A static variable declaration for the %extra_argument
**    ssiexprparserARG_PDECL     A parameter declaration for the %extra_argument
**    ssiexprparserARG_STORE     Code to store %extra_argument into yypParser
**    ssiexprparserARG_FETCH     Code to extract %extra_argument from yypParser
**    YYNSTATE           the combined number of states.
**    YYNRULE            the number of rules in the grammar
**    YYERRORSYMBOL      is the code number of the error symbol.  If not
**                       defined, then do no error processing.
*/
/*  */
#define YYCODETYPE unsigned char
#define YYNOCODE 20
#define YYACTIONTYPE unsigned char
#define ssiexprparserTOKENTYPE buffer *
typedef union {
  ssiexprparserTOKENTYPE yy0;
  int yy8;
  buffer * yy19;
  ssi_val_t * yy29;
  int yy39;
} YYMINORTYPE;
#define YYSTACKDEPTH 100
#define ssiexprparserARG_SDECL ssi_ctx_t *ctx;
#define ssiexprparserARG_PDECL ,ssi_ctx_t *ctx
#define ssiexprparserARG_FETCH ssi_ctx_t *ctx = yypParser->ctx
#define ssiexprparserARG_STORE yypParser->ctx = ctx
#define YYNSTATE 23
#define YYNRULE 16
#define YYERRORSYMBOL 13
#define YYERRSYMDT yy39
#define YY_NO_ACTION      (YYNSTATE+YYNRULE+2)
#define YY_ACCEPT_ACTION  (YYNSTATE+YYNRULE+1)
#define YY_ERROR_ACTION   (YYNSTATE+YYNRULE)

/* Next are that tables used to determine what action to take based on the
** current state and lookahead token.  These tables are used to implement
** functions that take a state number and lookahead value and return an
** action integer.
**
** Suppose the action integer is N.  Then the action is determined as
** follows
**
**   0 <= N < YYNSTATE                  Shift N.  That is, push the lookahead
**                                      token onto the stack and goto state N.
**
**   YYNSTATE <= N < YYNSTATE+YYNRULE   Reduce by rule N-YYNSTATE.
**
**   N == YYNSTATE+YYNRULE              A syntax error has occurred.
**
**   N == YYNSTATE+YYNRULE+1            The parser accepts its input.
**
**   N == YYNSTATE+YYNRULE+2            No such action.  Denotes unused
**                                      slots in the yy_action[] table.
**
** The action table is constructed as a single large table named yy_action[].
** Given state S and lookahead X, the action is computed as
**
**      yy_action[ yy_shift_ofst[S] + X ]
**
** If the index value yy_shift_ofst[S]+X is out of range or if the value
** yy_lookahead[yy_shift_ofst[S]+X] is not equal to X or if yy_shift_ofst[S]
** is equal to YY_SHIFT_USE_DFLT, it means that the action is not in the table
** and that yy_default[S] should be used instead.
**
** The formula above is for computing the action when the lookahead is
** a terminal symbol.  If the lookahead is a non-terminal (as occurs after
** a reduce action) then the yy_reduce_ofst[] array is used in place of
** the yy_shift_ofst[] array and YY_REDUCE_USE_DFLT is used in place of
** YY_SHIFT_USE_DFLT.
**
** The following are the tables generated in this section:
**
**  yy_action[]        A single table containing all actions.
**  yy_lookahead[]     A table containing the lookahead for each entry in
**                     yy_action.  Used to detect hash collisions.
**  yy_shift_ofst[]    For each state, the offset into yy_action for
**                     shifting terminals.
**  yy_reduce_ofst[]   For each state, the offset into yy_action for
**                     shifting non-terminals after a reduce.
**  yy_default[]       Default action for each state.
*/
static YYACTIONTYPE yy_action[] = {
 /*     0 */     5,    7,   17,   18,   22,   20,   21,   19,    2,   14,
 /*    10 */     1,   23,   40,    9,   11,    3,   16,    2,   14,   12,
 /*    20 */     4,   14,    5,    7,    6,   14,    7,    8,   14,   10,
 /*    30 */    14,   13,   37,   37,   15,
};
static YYCODETYPE yy_lookahead[] = {
 /*     0 */     1,    2,    3,    4,    5,    6,    7,    8,   14,   15,
 /*    10 */    16,    0,   18,    9,   10,   17,   12,   14,   15,   16,
 /*    20 */    14,   15,    1,    2,   14,   15,    2,   14,   15,   14,
 /*    30 */    15,   11,   19,   19,   12,
};
#define YY_SHIFT_USE_DFLT (-2)
static signed char yy_shift_ofst[] = {
 /*     0 */     4,   11,   -1,    4,   21,    4,   24,    4,   -2,    4,
 /*    10 */    -2,    4,   20,   -2,   22,   -2,   -2,   -2,   -2,   -2,
 /*    20 */    -2,   -2,   -2,
};
#define YY_REDUCE_USE_DFLT (-7)
static signed char yy_reduce_ofst[] = {
 /*     0 */    -6,   -7,   -2,    6,   -7,   10,   -7,   13,   -7,   15,
 /*    10 */    -7,    3,   -7,   -7,   -7,   -7,   -7,   -7,   -7,   -7,
 /*    20 */    -7,   -7,   -7,
};
static YYACTIONTYPE yy_default[] = {
 /*     0 */    39,   39,   25,   39,   24,   39,   26,   39,   27,   39,
 /*    10 */    28,   39,   39,   29,   30,   32,   31,   33,   34,   35,
 /*    20 */    36,   37,   38,
};
#define YY_SZ_ACTTAB (sizeof(yy_action)/sizeof(yy_action[0]))

/* The next table maps tokens into fallback tokens.  If a construct
** like the following:
**
**      %fallback ID X Y Z.
**
** appears in the grammer, then ID becomes a fallback token for X, Y,
** and Z.  Whenever one of the tokens X, Y, or Z is input to the parser
** but it does not parse, the type of the token is changed to ID and
** the parse is retried before an error is thrown.
*/
#ifdef YYFALLBACK
static const YYCODETYPE yyFallback[] = {
};
#endif /* YYFALLBACK */

/* The following structure represents a single element of the
** parser's stack.  Information stored includes:
**
**   +  The state number for the parser at this level of the stack.
**
**   +  The value of the token stored at this level of the stack.
**      (In other words, the "major" token.)
**
**   +  The semantic value stored at this level of the stack.  This is
**      the information used by the action routines in the grammar.
**      It is sometimes called the "minor" token.
*/
struct yyStackEntry {
  int stateno;       /* The state-number */
  int major;         /* The major token value.  This is the code
                     ** number for the token at this stack level */
  YYMINORTYPE minor; /* The user-supplied minor token value.  This
                     ** is the value of the token  */
};
typedef struct yyStackEntry yyStackEntry;

/* The state of the parser is completely contained in an instance of
** the following structure */
struct yyParser {
  int yyidx;                    /* Index of top element in stack */
  int yyerrcnt;                 /* Shifts left before out of the error */
  ssiexprparserARG_SDECL                /* A place to hold %extra_argument */
  yyStackEntry yystack[YYSTACKDEPTH];  /* The parser's stack */
};
typedef struct yyParser yyParser;

#ifndef NDEBUG
#include <stdio.h>
static FILE *yyTraceFILE = NULL;
static char *yyTracePrompt = NULL;
#endif /* NDEBUG */

#ifndef NDEBUG
/*
** Turn parser tracing on by giving a stream to which to write the trace
** and a prompt to preface each trace message.  Tracing is turned off
** by making either argument NULL
**
** Inputs:
** <ul>
** <li> A FILE* to which trace output should be written.
**      If NULL, then tracing is turned off.
** <li> A prefix string written at the beginning of every
**      line of trace output.  If NULL, then tracing is
**      turned off.
** </ul>
**
** Outputs:
** None.
*/
#if 0
void ssiexprparserTrace(FILE *TraceFILE, char *zTracePrompt){
  yyTraceFILE = TraceFILE;
  yyTracePrompt = zTracePrompt;
  if( yyTraceFILE==0 ) yyTracePrompt = 0;
  else if( yyTracePrompt==0 ) yyTraceFILE = 0;
}
#endif
#endif /* NDEBUG */

#ifndef NDEBUG
/* For tracing shifts, the names of all terminals and nonterminals
** are required.  The following table supplies these names */
static const char *yyTokenName[] = {
  "$",             "AND",           "OR",            "EQ",          
  "NE",            "GT",            "GE",            "LT",          
  "LE",            "NOT",           "LPARAN",        "RPARAN",      
  "VALUE",         "error",         "expr",          "value",       
  "exprline",      "cond",          "input",       
};
#endif /* NDEBUG */

#ifndef NDEBUG
/* For tracing reduce actions, the names of all rules are required.
*/
static const char *yyRuleName[] = {
 /*   0 */ "input ::= exprline",
 /*   1 */ "exprline ::= expr cond expr",
 /*   2 */ "exprline ::= expr",
 /*   3 */ "expr ::= expr AND expr",
 /*   4 */ "expr ::= expr OR expr",
 /*   5 */ "expr ::= NOT expr",
 /*   6 */ "expr ::= LPARAN exprline RPARAN",
 /*   7 */ "expr ::= value",
 /*   8 */ "value ::= VALUE",
 /*   9 */ "value ::= value VALUE",
 /*  10 */ "cond ::= EQ",
 /*  11 */ "cond ::= NE",
 /*  12 */ "cond ::= LE",
 /*  13 */ "cond ::= GE",
 /*  14 */ "cond ::= LT",
 /*  15 */ "cond ::= GT",
};
#endif /* NDEBUG */

/*
** This function returns the symbolic name associated with a token
** value.
*/
#if 0
const char *ssiexprparserTokenName(int tokenType){
#ifndef NDEBUG
  if( tokenType>0 && (size_t)tokenType<(sizeof(yyTokenName)/sizeof(yyTokenName[0])) ){
    return yyTokenName[tokenType];
  }else{
    return "Unknown";
  }
#else
  return "";
#endif
}
#endif

/*
** This function allocates a new parser.
** The only argument is a pointer to a function which works like
** malloc.
**
** Inputs:
** A pointer to the function used to allocate memory.
**
** Outputs:
** A pointer to a parser.  This pointer is used in subsequent calls
** to ssiexprparser and ssiexprparserFree.
*/
void *ssiexprparserAlloc(void *(*mallocProc)(size_t)){
  yyParser *pParser;
  pParser = (yyParser*)(*mallocProc)( (size_t)sizeof(yyParser) );
  if( pParser ){
    pParser->yyidx = -1;
  }
  return pParser;
}

/* The following function deletes the value associated with a
** symbol.  The symbol can be either a terminal or nonterminal.
** "yymajor" is the symbol code, and "yypminor" is a pointer to
** the value.
*/
static void yy_destructor(YYCODETYPE yymajor, YYMINORTYPE *yypminor){
  switch( yymajor ){
    /* Here is inserted the actions which take place when a
    ** terminal or non-terminal is destroyed.  This can happen
    ** when the symbol is popped from the stack during a
    ** reduce or during error processing or when a parser is
    ** being destroyed before it is finished parsing.
    **
    ** Note: during a reduce, the only symbols destroyed are those
    ** which appear on the RHS of the rule, but which are not used
    ** inside the C code.
    */
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
#line 22 "./mod_ssi_exprparser.y"
{ buffer_free((yypminor->yy0)); }
#line 352 "mod_ssi_exprparser.c"
      break;
    default:  break;   /* If no destructor action specified: do nothing */
  }
}

/*
** Pop the parser's stack once.
**
** If there is a destructor routine associated with the token which
** is popped from the stack, then call it.
**
** Return the major token number for the symbol popped.
*/
static int yy_pop_parser_stack(yyParser *pParser){
  YYCODETYPE yymajor;
  yyStackEntry *yytos = &pParser->yystack[pParser->yyidx];

  if( pParser->yyidx<0 ) return 0;
#ifndef NDEBUG
  if( yyTraceFILE && pParser->yyidx>=0 ){
    my_fprintf(yyTraceFILE,"%sPopping %s\n",
      yyTracePrompt,
      yyTokenName[yytos->major]);
  }
#endif
  yymajor = yytos->major;
  yy_destructor( yymajor, &yytos->minor);
  pParser->yyidx--;
  return yymajor;
}

/*
** Deallocate and destroy a parser.  Destructors are all called for
** all stack elements before shutting the parser down.
**
** Inputs:
** <ul>
** <li>  A pointer to the parser.  This should be a pointer
**       obtained from ssiexprparserAlloc.
** <li>  A pointer to a function used to reclaim memory obtained
**       from malloc.
** </ul>
*/
void ssiexprparserFree(
  void *p,                    /* The parser to be deleted */
  void (*freeProc)(void*)     /* Function used to reclaim memory */
){
  yyParser *pParser = (yyParser*)p;
  if( pParser==NULL ) return;
  while( pParser->yyidx>=0 ) yy_pop_parser_stack(pParser);
  (*freeProc)((void*)pParser);
}

/*
** Find the appropriate action for a parser given the terminal
** look-ahead token iLookAhead.
**
** If the look-ahead token is YYNOCODE, then check to see if the action is
** independent of the look-ahead.  If it is, return the action, otherwise
** return YY_NO_ACTION.
*/
static int yy_find_shift_action(
  yyParser *pParser,        /* The parser */
  int iLookAhead            /* The look-ahead token */
){
  int i;
  int stateno = pParser->yystack[pParser->yyidx].stateno;

  /* if( pParser->yyidx<0 ) return YY_NO_ACTION;  */
  i = yy_shift_ofst[stateno];
  if( i==YY_SHIFT_USE_DFLT ){
    return yy_default[stateno];
  }
  if( iLookAhead==YYNOCODE ){
    return YY_NO_ACTION;
  }
  i += iLookAhead;
  if( i<0 || (size_t)i>=YY_SZ_ACTTAB || yy_lookahead[i]!=iLookAhead ){
#ifdef YYFALLBACK
    int iFallback;            /* Fallback token */
    if( iLookAhead<sizeof(yyFallback)/sizeof(yyFallback[0])
           && (iFallback = yyFallback[iLookAhead])!=0 ){
#ifndef NDEBUG
      if( yyTraceFILE ){
        my_fprintf(yyTraceFILE, "%sFALLBACK %s => %s\n",
           yyTracePrompt, yyTokenName[iLookAhead], yyTokenName[iFallback]);
      }
#endif
      return yy_find_shift_action(pParser, iFallback);
    }
#endif
    return yy_default[stateno];
  }else{
    return yy_action[i];
  }
}

/*
** Find the appropriate action for a parser given the non-terminal
** look-ahead token iLookAhead.
**
** If the look-ahead token is YYNOCODE, then check to see if the action is
** independent of the look-ahead.  If it is, return the action, otherwise
** return YY_NO_ACTION.
*/
static int yy_find_reduce_action(
  yyParser *pParser,        /* The parser */
  int iLookAhead            /* The look-ahead token */
){
  int i;
  int stateno = pParser->yystack[pParser->yyidx].stateno;

  i = yy_reduce_ofst[stateno];
  if( i==YY_REDUCE_USE_DFLT ){
    return yy_default[stateno];
  }
  if( iLookAhead==YYNOCODE ){
    return YY_NO_ACTION;
  }
  i += iLookAhead;
  if( i<0 || (size_t)i>=YY_SZ_ACTTAB || yy_lookahead[i]!=iLookAhead ){
    return yy_default[stateno];
  }else{
    return yy_action[i];
  }
}

/*
** Perform a shift action.
*/
static void yy_shift(
  yyParser *yypParser,          /* The parser to be shifted */
  int yyNewState,               /* The new state to shift in */
  int yyMajor,                  /* The major token to shift in */
  YYMINORTYPE *yypMinor         /* Pointer ot the minor token to shift in */
){
  yyStackEntry *yytos;
  yypParser->yyidx++;
  if( yypParser->yyidx>=YYSTACKDEPTH ){
     ssiexprparserARG_FETCH;
     yypParser->yyidx--;
#ifndef NDEBUG
     if( yyTraceFILE ){
       my_fprintf(yyTraceFILE,"%sStack Overflow!\n",yyTracePrompt);
     }
#endif
     while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
     /* Here code is inserted which will execute if the parser
     ** stack every overflows */
     ssiexprparserARG_STORE; /* Suppress warning about unused %extra_argument var */
     return;
  }
  yytos = &yypParser->yystack[yypParser->yyidx];
  yytos->stateno = yyNewState;
  yytos->major = yyMajor;
  yytos->minor = *yypMinor;
#ifndef NDEBUG
  if( yyTraceFILE && yypParser->yyidx>0 ){
    int i;
    my_fprintf(yyTraceFILE,"%sShift %d\n",yyTracePrompt,yyNewState);
    my_fprintf(yyTraceFILE,"%sStack:",yyTracePrompt);
    for(i=1; i<=yypParser->yyidx; i++)
      my_fprintf(yyTraceFILE," %s",yyTokenName[yypParser->yystack[i].major]);
    my_fprintf(yyTraceFILE,"\n");
  }
#endif
}

/* The following table contains information about every rule that
** is used during the reduce.
*/
static struct {
  YYCODETYPE lhs;         /* Symbol on the left-hand side of the rule */
  unsigned char nrhs;     /* Number of right-hand side symbols in the rule */
} yyRuleInfo[] = {
  { 18, 1 },
  { 16, 3 },
  { 16, 1 },
  { 14, 3 },
  { 14, 3 },
  { 14, 2 },
  { 14, 3 },
  { 14, 1 },
  { 15, 1 },
  { 15, 2 },
  { 17, 1 },
  { 17, 1 },
  { 17, 1 },
  { 17, 1 },
  { 17, 1 },
  { 17, 1 },
};

static void yy_accept(yyParser*);  /* Forward Declaration */

/*
** Perform a reduce action and the shift that must immediately
** follow the reduce.
*/
static void yy_reduce(
  yyParser *yypParser,         /* The parser */
  int yyruleno                 /* Number of the rule by which to reduce */
){
  int yygoto;                     /* The next state */
  int yyact;                      /* The next action */
  YYMINORTYPE yygotominor;        /* The LHS of the rule reduced */
  yyStackEntry *yymsp;            /* The top of the parser's stack */
  int yysize;                     /* Amount to pop the stack */
  ssiexprparserARG_FETCH;
  yymsp = &yypParser->yystack[yypParser->yyidx];
#ifndef NDEBUG
  if( yyTraceFILE && yyruleno>=0
        && (size_t)yyruleno<sizeof(yyRuleName)/sizeof(yyRuleName[0]) ){
    my_fprintf(yyTraceFILE, "%sReduce [%s].\n", yyTracePrompt,
      yyRuleName[yyruleno]);
  }
#endif /* NDEBUG */

  switch( yyruleno ){
  /* Beginning here are the reduction cases.  A typical example
  ** follows:
  **   case 0:
  **  #line <lineno> <grammarfile>
  **     { ... }           // User supplied code
  **  #line <lineno> <thisfile>
  **     break;
  */
      case 0:
#line 29 "./mod_ssi_exprparser.y"
{
  ctx->val.bo = ssi_val_tobool(yymsp[0].minor.yy29);
  ctx->val.type = SSI_TYPE_BOOL;

  ssi_val_free(yymsp[0].minor.yy29);
}
#line 588 "mod_ssi_exprparser.c"
        break;
      case 1:
#line 36 "./mod_ssi_exprparser.y"
{
  int cmp;

  if (yymsp[-2].minor.yy29->type == SSI_TYPE_STRING &&
      yymsp[0].minor.yy29->type == SSI_TYPE_STRING) {
       cmp = strcmp(yymsp[-2].minor.yy29->str->ptr, yymsp[0].minor.yy29->str->ptr);
  } else {
    cmp = ssi_val_tobool(yymsp[-2].minor.yy29) - ssi_val_tobool(yymsp[0].minor.yy29);
  }

  yygotominor.yy29 = yymsp[-2].minor.yy29;

  switch(yymsp[-1].minor.yy8) {
  case SSI_COND_EQ: yygotominor.yy29->bo = (cmp == 0) ? 1 : 0; break;
  case SSI_COND_NE: yygotominor.yy29->bo = (cmp != 0) ? 1 : 0; break;
  case SSI_COND_GE: yygotominor.yy29->bo = (cmp >= 0) ? 1 : 0; break;
  case SSI_COND_GT: yygotominor.yy29->bo = (cmp > 0) ? 1 : 0; break;
  case SSI_COND_LE: yygotominor.yy29->bo = (cmp <= 0) ? 1 : 0; break;
  case SSI_COND_LT: yygotominor.yy29->bo = (cmp < 0) ? 1 : 0; break;
  }

  yygotominor.yy29->type = SSI_TYPE_BOOL;

  ssi_val_free(yymsp[0].minor.yy29);
}
#line 617 "mod_ssi_exprparser.c"
        break;
      case 2:
#line 61 "./mod_ssi_exprparser.y"
{
  yygotominor.yy29 = yymsp[0].minor.yy29;
}
#line 624 "mod_ssi_exprparser.c"
        break;
      case 3:
#line 64 "./mod_ssi_exprparser.y"
{
  int e;

  e = ssi_val_tobool(yymsp[-2].minor.yy29) && ssi_val_tobool(yymsp[0].minor.yy29);

  yygotominor.yy29 = yymsp[-2].minor.yy29;
  yygotominor.yy29->bo = e;
  yygotominor.yy29->type = SSI_TYPE_BOOL;
  ssi_val_free(yymsp[0].minor.yy29);
}
#line 638 "mod_ssi_exprparser.c"
  yy_destructor(1,&yymsp[-1].minor);
        break;
      case 4:
#line 75 "./mod_ssi_exprparser.y"
{
  int e;

  e = ssi_val_tobool(yymsp[-2].minor.yy29) || ssi_val_tobool(yymsp[0].minor.yy29);

  yygotominor.yy29 = yymsp[-2].minor.yy29;
  yygotominor.yy29->bo = e;
  yygotominor.yy29->type = SSI_TYPE_BOOL;
  ssi_val_free(yymsp[0].minor.yy29);
}
#line 653 "mod_ssi_exprparser.c"
  yy_destructor(2,&yymsp[-1].minor);
        break;
      case 5:
#line 86 "./mod_ssi_exprparser.y"
{
  int e;

  e = !ssi_val_tobool(yymsp[0].minor.yy29);

  yygotominor.yy29 = yymsp[0].minor.yy29;
  yygotominor.yy29->bo = e;
  yygotominor.yy29->type = SSI_TYPE_BOOL;
}
#line 667 "mod_ssi_exprparser.c"
  yy_destructor(9,&yymsp[-1].minor);
        break;
      case 6:
#line 95 "./mod_ssi_exprparser.y"
{
  yygotominor.yy29 = yymsp[-1].minor.yy29;
}
#line 675 "mod_ssi_exprparser.c"
  yy_destructor(10,&yymsp[-2].minor);
  yy_destructor(11,&yymsp[0].minor);
        break;
      case 7:
#line 99 "./mod_ssi_exprparser.y"
{
  yygotominor.yy29 = ssi_val_init();
  yygotominor.yy29->str = yymsp[0].minor.yy19;
  yygotominor.yy29->type = SSI_TYPE_STRING;
}
#line 686 "mod_ssi_exprparser.c"
        break;
      case 8:
#line 105 "./mod_ssi_exprparser.y"
{
  yygotominor.yy19 = yymsp[0].minor.yy0;
}
#line 693 "mod_ssi_exprparser.c"
        break;
      case 9:
#line 109 "./mod_ssi_exprparser.y"
{
  yygotominor.yy19 = yymsp[-1].minor.yy19;
  buffer_append_string_buffer(yygotominor.yy19, yymsp[0].minor.yy0);
  buffer_free(yymsp[0].minor.yy0);
}
#line 702 "mod_ssi_exprparser.c"
        break;
      case 10:
#line 115 "./mod_ssi_exprparser.y"
{ yygotominor.yy8 = SSI_COND_EQ; }
#line 707 "mod_ssi_exprparser.c"
  yy_destructor(3,&yymsp[0].minor);
        break;
      case 11:
#line 116 "./mod_ssi_exprparser.y"
{ yygotominor.yy8 = SSI_COND_NE; }
#line 713 "mod_ssi_exprparser.c"
  yy_destructor(4,&yymsp[0].minor);
        break;
      case 12:
#line 117 "./mod_ssi_exprparser.y"
{ yygotominor.yy8 = SSI_COND_LE; }
#line 719 "mod_ssi_exprparser.c"
  yy_destructor(8,&yymsp[0].minor);
        break;
      case 13:
#line 118 "./mod_ssi_exprparser.y"
{ yygotominor.yy8 = SSI_COND_GE; }
#line 725 "mod_ssi_exprparser.c"
  yy_destructor(6,&yymsp[0].minor);
        break;
      case 14:
#line 119 "./mod_ssi_exprparser.y"
{ yygotominor.yy8 = SSI_COND_LT; }
#line 731 "mod_ssi_exprparser.c"
  yy_destructor(7,&yymsp[0].minor);
        break;
      case 15:
#line 120 "./mod_ssi_exprparser.y"
{ yygotominor.yy8 = SSI_COND_GT; }
#line 737 "mod_ssi_exprparser.c"
  yy_destructor(5,&yymsp[0].minor);
        break;
  };
  yygoto = yyRuleInfo[yyruleno].lhs;
  yysize = yyRuleInfo[yyruleno].nrhs;
  yypParser->yyidx -= yysize;
  yyact = yy_find_reduce_action(yypParser,yygoto);
  if( yyact < YYNSTATE ){
    yy_shift(yypParser,yyact,yygoto,&yygotominor);
  }else if( yyact == YYNSTATE + YYNRULE + 1 ){
    yy_accept(yypParser);
  }
}

/*
** The following code executes when the parse fails
*/
static void yy_parse_failed(
  yyParser *yypParser           /* The parser */
){
  ssiexprparserARG_FETCH;
#ifndef NDEBUG
  if( yyTraceFILE ){
    my_fprintf(yyTraceFILE,"%sFail!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser fails */
#line 14 "./mod_ssi_exprparser.y"

  ctx->ok = 0;

#line 771 "mod_ssi_exprparser.c"
  ssiexprparserARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/*
** The following code executes when a syntax error first occurs.
*/
static void yy_syntax_error(
  yyParser *yypParser,           /* The parser */
  int yymajor,                   /* The major type of the error token */
  YYMINORTYPE yyminor            /* The minor type of the error token */
){
  ssiexprparserARG_FETCH;
  UNUSED(yymajor);
  UNUSED(yyminor);
#define TOKEN (yyminor.yy0)
  ssiexprparserARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/*
** The following is executed when the parser accepts
*/
static void yy_accept(
  yyParser *yypParser           /* The parser */
){
  ssiexprparserARG_FETCH;
#ifndef NDEBUG
  if( yyTraceFILE ){
    my_fprintf(yyTraceFILE,"%sAccept!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser accepts */
  ssiexprparserARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/* The main parser program.
** The first argument is a pointer to a structure obtained from
** "ssiexprparserAlloc" which describes the current state of the parser.
** The second argument is the major token number.  The third is
** the minor token.  The fourth optional argument is whatever the
** user wants (and specified in the grammar) and is available for
** use by the action routines.
**
** Inputs:
** <ul>
** <li> A pointer to the parser (an opaque structure.)
** <li> The major token number.
** <li> The minor token number.
** <li> An option argument of a grammar-specified type.
** </ul>
**
** Outputs:
** None.
*/
void ssiexprparser(
  void *yyp,                   /* The parser */
  int yymajor,                 /* The major token code number */
  ssiexprparserTOKENTYPE yyminor       /* The value for the token */
  ssiexprparserARG_PDECL               /* Optional %extra_argument parameter */
){
  YYMINORTYPE yyminorunion;
  int yyact;            /* The parser action. */
  int yyendofinput;     /* True if we are at the end of input */
  int yyerrorhit = 0;   /* True if yymajor has invoked an error */
  yyParser *yypParser;  /* The parser */

  /* (re)initialize the parser, if necessary */
  yypParser = (yyParser*)yyp;
  if( yypParser->yyidx<0 ){
    if( yymajor==0 ) return;
    yypParser->yyidx = 0;
    yypParser->yyerrcnt = -1;
    yypParser->yystack[0].stateno = 0;
    yypParser->yystack[0].major = 0;
  }
  yyminorunion.yy0 = yyminor;
  yyendofinput = (yymajor==0);
  ssiexprparserARG_STORE;

#ifndef NDEBUG
  if( yyTraceFILE ){
    my_fprintf(yyTraceFILE,"%sInput %s\n",yyTracePrompt,yyTokenName[yymajor]);
  }
#endif

  do{
    yyact = yy_find_shift_action(yypParser,yymajor);
    if( yyact<YYNSTATE ){
      yy_shift(yypParser,yyact,yymajor,&yyminorunion);
      yypParser->yyerrcnt--;
      if( yyendofinput && yypParser->yyidx>=0 ){
        yymajor = 0;
      }else{
        yymajor = YYNOCODE;
      }
    }else if( yyact < YYNSTATE + YYNRULE ){
      yy_reduce(yypParser,yyact-YYNSTATE);
    }else if( yyact == YY_ERROR_ACTION ){
      int yymx;
#ifndef NDEBUG
      if( yyTraceFILE ){
        my_fprintf(yyTraceFILE,"%sSyntax Error!\n",yyTracePrompt);
      }
#endif
#ifdef YYERRORSYMBOL
      /* A syntax error has occurred.
      ** The response to an error depends upon whether or not the
      ** grammar defines an error token "ERROR".
      **
      ** This is what we do if the grammar does define ERROR:
      **
      **  * Call the %syntax_error function.
      **
      **  * Begin popping the stack until we enter a state where
      **    it is legal to shift the error symbol, then shift
      **    the error symbol.
      **
      **  * Set the error count to three.
      **
      **  * Begin accepting and shifting new tokens.  No new error
      **    processing will occur until three tokens have been
      **    shifted successfully.
      **
      */
      if( yypParser->yyerrcnt<0 ){
        yy_syntax_error(yypParser,yymajor,yyminorunion);
      }
      yymx = yypParser->yystack[yypParser->yyidx].major;
      if( yymx==YYERRORSYMBOL || yyerrorhit ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          my_fprintf(yyTraceFILE,"%sDiscard input token %s\n",
             yyTracePrompt,yyTokenName[yymajor]);
        }
#endif
        yy_destructor(yymajor,&yyminorunion);
        yymajor = YYNOCODE;
      }else{
         while(
          yypParser->yyidx >= 0 &&
          yymx != YYERRORSYMBOL &&
          (yyact = yy_find_shift_action(yypParser,YYERRORSYMBOL)) >= YYNSTATE
        ){
          yy_pop_parser_stack(yypParser);
        }
        if( yypParser->yyidx < 0 || yymajor==0 ){
          yy_destructor(yymajor,&yyminorunion);
          yy_parse_failed(yypParser);
          yymajor = YYNOCODE;
        }else if( yymx!=YYERRORSYMBOL ){
          YYMINORTYPE u2;
          u2.YYERRSYMDT = 0;
          yy_shift(yypParser,yyact,YYERRORSYMBOL,&u2);
        }
      }
      yypParser->yyerrcnt = 3;
      yyerrorhit = 1;
#else  /* YYERRORSYMBOL is not defined */
      /* This is what we do if the grammar does not define ERROR:
      **
      **  * Report an error message, and throw away the input token.
      **
      **  * If the input token is $, then fail the parse.
      **
      ** As before, subsequent error messages are suppressed until
      ** three input tokens have been successfully shifted.
      */
      if( yypParser->yyerrcnt<=0 ){
        yy_syntax_error(yypParser,yymajor,yyminorunion);
      }
      yypParser->yyerrcnt = 3;
      yy_destructor(yymajor,&yyminorunion);
      if( yyendofinput ){
        yy_parse_failed(yypParser);
      }
      yymajor = YYNOCODE;
#endif
    }else{
      yy_accept(yypParser);
      yymajor = YYNOCODE;
    }
  }while( yymajor!=YYNOCODE && yypParser->yyidx>=0 );
  return;
}
