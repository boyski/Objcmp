#ifndef	_UNSTAMP_H
#define	_UNSTAMP_H

#ifdef	__cplusplus
extern "C" {
#endif	/*__cplusplus*/

// Patch any timestamps or similar in an EXE/DLL/OBJ.
// If file format is not recognized the data is unmodified.
int unstamp(void *, off_t *);

#ifdef	__cplusplus
}
#endif	/*__cplusplus*/

#endif	/*_UNSTAMP_H*/
