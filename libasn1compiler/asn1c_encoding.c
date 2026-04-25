/*
 * Encoding control processing for asn1c compiler
 * Handles ENCODING-CONTROL directives from ASN.1 modules
 */
#include "asn1c_internal.h"
#include "asn1c_encoding.h"
#include "asn1_common.h"
#include <asn1fix_export.h>
#include <asn1_namespace.h>

/*
 * Helper function to get string name for encoding type (for debug messages)
 */
static const char * CC_NOTUSED
encoding_type_name(enum asn1p_encoding_control_type_e type) {
    switch(type) {
    case EC_XER_HEXADECIMAL: return "hexadecimal";
    case EC_XER_BASE64: return "base64";
    case EC_XER_UTF8: return "utf8";
    case EC_NONE:
    default: return "none";
    }
}

/*
 * Apply encoding controls from ENCODING-CONTROL sections to type definitions.
 * 
 * This function iterates through module members to find encoding instructions
 * (identified by having encoding_control.encoding_type != EC_NONE), then matches
 * them to type definitions by identifier name and copies the encoding settings.
 */
int
asn1c_apply_encoding_controls(asn1p_t *asn, asn1p_module_t *mod) {
    asn1p_expr_t *instr;
    asn1p_expr_t *type_def;
    int applied = 0;
    int warnings = 0;
    
    if(!asn || !mod) return -1;
    
    /* Iterate through module members to find encoding instructions */
    TQ_FOR(instr, &(mod->members), next) {
        /* Skip if not explicitly marked as an encoding instruction */
        if((instr->_mark & TM_ENCODING_INSTRUCTION) == 0) {
            continue;
        }
        /* Skip if no encoding control is actually set */
        if(instr->encoding_control.encoding_type == EC_NONE) {
            continue;
        }
        
        if(!instr->Identifier) {
            continue;  /* Shouldn't happen, but be safe */
        }
        
        /* Find matching type definition */
        int found = 0;
        TQ_FOR(type_def, &(mod->members), next) {
            /* Skip the instruction itself */
            if(type_def == instr) continue;
            
            /* Skip if no identifier */
            if(!type_def->Identifier) continue;
            
            /* Match by identifier name */
            if(strcmp(type_def->Identifier, instr->Identifier) == 0) {
                /* Verify type compatibility */
                asn1p_expr_type_e target_type = type_def->expr_type;
                
                /* Resolve through references if needed */
                if(target_type == A1TC_REFERENCE && type_def->reference) {
                    asn1p_expr_t *resolved = WITH_MODULE_NAMESPACE(
                        type_def->module, expr_ns,
                        asn1f_find_terminal_type_ex(asn, expr_ns, type_def));
                    if(resolved) {
                        target_type = resolved->expr_type;
                    }
                }
                
                /* Check if encoding control is applicable to this type */
                if(target_type == ASN_BASIC_OCTET_STRING ||
                   target_type == A1TC_REFERENCE) {
                    
                    /* Apply encoding control - deep copy */
                    type_def->encoding_control.encoding_type = instr->encoding_control.encoding_type;
                    if(type_def->encoding_control.encoding_reference != NULL) {
                        free(type_def->encoding_control.encoding_reference);
                        type_def->encoding_control.encoding_reference = NULL;
                    }
                    if(instr->encoding_control.encoding_reference) {
                        type_def->encoding_control.encoding_reference =
                            strdup(instr->encoding_control.encoding_reference);
                        if(type_def->encoding_control.encoding_reference == NULL) {
                            fprintf(stderr,
                                "ERROR: Failed to allocate memory for encoding_reference\n");
                        }
                    } else {
                        type_def->encoding_control.encoding_reference = NULL;
                    }
                    
                    applied++;
                    found = 1;
                    break;
                } else {
                    fprintf(stderr,
                        "WARNING: Encoding control for '%s' at line %d "
                        "cannot be applied to non-OCTET STRING type\n",
                        instr->Identifier, 
                        instr->_lineno);
                    warnings++;
                    found = 1;
                    break;
                }
            }
        }
        
        if(!found) {
            fprintf(stderr,
                "WARNING: No type definition found for encoding control '%s' at line %d\n",
                instr->Identifier,
                instr->_lineno);
            warnings++;
        }
    }
    
    if(applied > 0) {
        fprintf(stderr,
            "NOTE: Applied %d encoding control directive(s) in module %s\n",
            applied, mod->ModuleName);
    }
    
    if(warnings > 0) {
        fprintf(stderr,
            "NOTE: %d encoding control warning(s) in module %s\n",
            warnings, mod->ModuleName);
    }
    
    return applied;
}
